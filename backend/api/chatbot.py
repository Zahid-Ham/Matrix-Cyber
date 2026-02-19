from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from core.database import get_db
from core.logger import get_logger
from core.chatbot import SASTChatbot
from models.user import User
from models.scan import Scan
from models.vulnerability import Vulnerability
from schemas.chat import ChatRequest, ChatResponse, ArtifactChatRequest
import schemas.chat
from api.deps import get_current_user
from config import settings

logger = get_logger(__name__)

router = APIRouter(prefix="/chat", tags=["Chatbot"])

# Global or session-based chatbot instance?
# For now, we'll create a new one per request or use a simple singleton
# Since it's stateless (we pass the history back or keep it in the assistant), 
# we can just initialize it on the fly.
chatbot = SASTChatbot()

async def get_scan_context(scan_id: int, user_id: int, db: AsyncSession) -> str:
    """Fetch and format scan results as a context string for the AI."""
    # Verify scan belongs to user
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
    )
    scan = scan_result.scalar_one_or_none()
    
    if not scan:
        return ""
    
    # Fetch vulnerabilities
    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    vulnerabilities = vuln_result.scalars().all()
    
    if not vulnerabilities:
        return f"Scan of {scan.target_url} completed. No vulnerabilities found."
    
    context = f"SCAN REPORT for {scan.target_url}\n"
    context += f"Total findings: {len(vulnerabilities)}\n\n"
    
    for i, v in enumerate(vulnerabilities):
        context += f"FINDING #{i+1}: {v.title}\n"
        context += f"- Type: {v.vulnerability_type.value}\n"
        context += f"- Severity: {v.severity.value}\n"
        context += f"- File: {v.file_path or 'N/A'}\n"
        context += f"- URL: {v.url}\n"
        context += f"- Description: {v.description}\n"
        if v.ai_analysis:
             context += f"- AI Analysis: {v.ai_analysis}\n"
        if v.remediation:
             context += f"- Recommendation: {v.remediation}\n"
        context += "---\n"
        
    return context

@router.post("/", response_model=ChatResponse)
async def chat_with_matrix(
    request: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Send a message to the security expert chatbot.
    If scan_id is provided, findings from that scan are used as context.
    """
    try:
        # Load context if scan_id is provided
        if request.scan_id:
            logger.info(f"Loading scan context for scan_id: {request.scan_id}")
            context = await get_scan_context(request.scan_id, current_user.id, db)
            if context:
                chatbot.set_scan_context(context)
            else:
                logger.warning(f"Scan context empty or unauthorized for scan_id: {request.scan_id}")
        
        # Call chatbot
        response_text = await chatbot.chat(request.message)
        
        return ChatResponse(
            response=response_text,
            metadata=chatbot.get_conversation_metadata(),
            suggested_questions=chatbot.get_suggested_questions()
        )
        
    except Exception as e:
        logger.error(f"Chatbot error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Chatbot failed: {str(e)}"
        )

    return {"status": "ok", "message": "Conversation reset"}

@router.post("/artifact", response_model=ChatResponse)
async def chat_about_artifact(
    request: schemas.chat.ArtifactChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Chat about a specific forensic artifact (vulnerability/finding).
    Provides context-aware responses and remediation suggestions.
    """
    from models.forensic import ForensicArtifact
    
    # 1. Fetch Artifact
    query = select(ForensicArtifact).where(ForensicArtifact.artifact_evidence_id == request.artifact_id)
    result = await db.execute(query)
    artifact = result.scalar_one_or_none()
    
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")

    # 2. Build Context
    metadata = artifact.metadata_json or {}
    file_path = metadata.get('file_path', 'Unknown file')
    
    # Try to get code/evidence
    evidence = artifact.raw_data or ""
    if not evidence and metadata.get('code_snippet'):
        evidence = metadata.get('code_snippet')
        
    context_prompt = f"""
CONTEXT: You are analyzing a specific security finding.
ARTIFACT: {artifact.name}
TYPE: {artifact.artifact_type}
FILE: {file_path}

EVIDENCE/CODE:
```
{evidence}
```

METADATA:
{metadata}

USER QUESTION: {request.message}

INSTRUCTIONS:
- Answer the user's question specifically about this artifact.
- If asked to fix it, provide a complete, corrected code block.
- Explain the logic of the fix.
- If the finding is a false positive, explain why.
"""

    # 3. Call AI
    import core.groq_client
    
    messages = [{"role": "system", "content": "You are a specialized security remediation assistant."}]
    # Add history
    messages.extend(request.history)
    messages.append({"role": "user", "content": context_prompt})
    
    try:
         response_data = await core.groq_client.chatbot_generate(
            messages=messages,
            model=settings.groq_model_chatbot
        )
         response_text = response_data.get('content', 'No response generated.')
         
         # 4. Extract suggested fix if present (basic heuristic)
         suggested_fix = None
         if "```" in response_text:
             # Very simple extraction, the frontend does better
             pass
         
         return ChatResponse(
             response=response_text,
             suggested_fix=response_text if "```" in response_text else None, # Frontend parses this better
             metadata={"artifact_id": request.artifact_id}
         )
         
    except Exception as e:
        logger.error(f"Artifact chat failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
