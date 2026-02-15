"""
GitHub Token Management API endpoints.
Allows users to configure their own GitHub Personal Access Tokens.
"""
import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from datetime import datetime, timezone

from core.database import get_db
from core.encryption import encrypt_token, decrypt_token
from models.user import User
from models.user_settings import UserSettings
from api.deps import get_current_user

router = APIRouter(prefix="/auth/settings", tags=["User Settings"])


class GitHubTokenRequest(BaseModel):
    """Request model for saving GitHub token."""
    token: str


class GitHubTokenStatus(BaseModel):
    """Response model for GitHub token status."""
    configured: bool
    username: str | None = None
    valid: bool = False
    last_validated: str | None = None


@router.post("/github-token/")
async def save_github_token(
    token_data: GitHubTokenRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Save or update user's GitHub Personal Access Token.
    The token will be encrypted before storage.
    """
    # Validate token format (basic check)
    if not token_data.token or len(token_data.token) < 20:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid GitHub token format"
        )
    
    # Validate token with GitHub API
    try:
        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {token_data.token}",
                "Accept": "application/vnd.github+json"
            }
            response = await client.get("https://api.github.com/user", headers=headers, timeout=10.0)
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid GitHub token. Please check your token and try again."
                )
            
            github_user = response.json()
            github_username = github_user.get("login")
    
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=status.HTTP_408_REQUEST_TIMEOUT,
            detail="GitHub API request timed out. Please try again."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to validate GitHub token: {str(e)}"
        )
    
    # Encrypt the token
    try:
        encrypted_token = encrypt_token(token_data.token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to encrypt token. Please contact support."
        )
    
    # Get or create user settings
    query = select(UserSettings).where(UserSettings.user_id == current_user.id)
    result = await db.execute(query)
    user_settings = result.scalar_one_or_none()
    
    if not user_settings:
        user_settings = UserSettings(user_id=current_user.id)
        db.add(user_settings)
    
    # Update settings
    user_settings.github_token_encrypted = encrypted_token
    user_settings.github_username = github_username
    user_settings.github_token_valid = True
    user_settings.github_token_last_validated = datetime.now(timezone.utc)
    user_settings.updated_at = datetime.now(timezone.utc)
    
    await db.commit()
    
    return {
        "message": "GitHub token saved successfully",
        "username": github_username,
        "configured": True
    }


@router.get("/github-token/status/", response_model=GitHubTokenStatus)
async def get_github_token_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get the status of user's GitHub token configuration."""
    query = select(UserSettings).where(UserSettings.user_id == current_user.id)
    result = await db.execute(query)
    user_settings = result.scalar_one_or_none()
    
    if not user_settings or not user_settings.github_token_encrypted:
        return GitHubTokenStatus(configured=False)
    
    return GitHubTokenStatus(
        configured=True,
        username=user_settings.github_username,
        valid=user_settings.github_token_valid,
        last_validated=user_settings.github_token_last_validated.isoformat() if user_settings.github_token_last_validated else None
    )


@router.delete("/github-token/")
async def delete_github_token(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete user's GitHub token."""
    query = select(UserSettings).where(UserSettings.user_id == current_user.id)
    result = await db.execute(query)
    user_settings = result.scalar_one_or_none()
    
    if not user_settings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No settings found"
        )
    
    # Clear GitHub token fields
    user_settings.github_token_encrypted = None
    user_settings.github_username = None
    user_settings.github_token_valid = False
    user_settings.github_token_last_validated = None
    user_settings.updated_at = datetime.now(timezone.utc)
    
    await db.commit()
    
    return {"message": "GitHub token deleted successfully"}


@router.post("/github-token/validate/")
async def validate_github_token(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Validate the stored GitHub token."""
    query = select(UserSettings).where(UserSettings.user_id == current_user.id)
    result = await db.execute(query)
    user_settings = result.scalar_one_or_none()
    
    if not user_settings or not user_settings.github_token_encrypted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No GitHub token configured"
        )
    
    # Decrypt token
    try:
        decrypted_token = decrypt_token(user_settings.github_token_encrypted)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt token. The encryption key may have changed."
        )
    
    # Validate with GitHub API
    try:
        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {decrypted_token}",
                "Accept": "application/vnd.github+json"
            }
            response = await client.get("https://api.github.com/user", headers=headers, timeout=10.0)
            
            is_valid = response.status_code == 200
            
            # Update validation status
            user_settings.github_token_valid = is_valid
            user_settings.github_token_last_validated = datetime.now(timezone.utc)
            await db.commit()
            
            if not is_valid:
                return {
                    "valid": False,
                    "message": "Token is invalid or expired. Please update your token."
                }
            
            github_user = response.json()
            return {
                "valid": True,
                "username": github_user.get("login"),
                "message": "Token is valid"
            }
    
    except Exception as e:
        return {
            "valid": False,
            "message": f"Validation failed: {str(e)}"
        }


async def get_user_github_token(user_id: int, db: AsyncSession) -> str | None:
    """
    Helper function to get decrypted GitHub token for a user.
    Returns None if no token is configured.
    """
    query = select(UserSettings).where(UserSettings.user_id == user_id)
    result = await db.execute(query)
    user_settings = result.scalar_one_or_none()
    
    if not user_settings or not user_settings.github_token_encrypted:
        return None
    
    try:
        return decrypt_token(user_settings.github_token_encrypted)
    except Exception:
        return None
