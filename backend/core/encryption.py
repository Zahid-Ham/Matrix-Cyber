"""
Encryption utilities for sensitive data storage.
Uses Fernet symmetric encryption to encrypt/decrypt user tokens.
"""
import os
import logging
from cryptography.fernet import Fernet
from typing import Optional

logger = logging.getLogger(__name__)


class EncryptionManager:
    """Manages encryption and decryption of sensitive data."""
    
    def __init__(self):
        """Initialize encryption manager with key from environment."""
        # Get encryption key from environment or generate one
        self.encryption_key = os.getenv('ENCRYPTION_KEY')
        
        if not self.encryption_key:
            logger.warning("ENCRYPTION_KEY not found in environment. Generating a new key.")
            logger.warning("IMPORTANT: Add this key to your .env file to persist encrypted data across restarts:")
            self.encryption_key = Fernet.generate_key().decode()
            logger.warning(f"ENCRYPTION_KEY={self.encryption_key}")
        
        # Ensure key is bytes
        if isinstance(self.encryption_key, str):
            self.encryption_key = self.encryption_key.encode()
        
        try:
            self.cipher = Fernet(self.encryption_key)
        except Exception as e:
            logger.error(f"Failed to initialize encryption cipher: {e}")
            raise ValueError("Invalid encryption key. Please check ENCRYPTION_KEY in .env")
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string.
        
        Args:
            plaintext: The string to encrypt
            
        Returns:
            Base64-encoded encrypted string
        """
        if not plaintext:
            return ""
        
        try:
            encrypted_bytes = self.cipher.encrypt(plaintext.encode())
            return encrypted_bytes.decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise ValueError("Failed to encrypt data")
    
    def decrypt(self, encrypted: str) -> str:
        """
        Decrypt an encrypted string.
        
        Args:
            encrypted: Base64-encoded encrypted string
            
        Returns:
            Decrypted plaintext string
        """
        if not encrypted:
            return ""
        
        try:
            decrypted_bytes = self.cipher.decrypt(encrypted.encode())
            return decrypted_bytes.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError("Failed to decrypt data. The encryption key may have changed.")


# Global instance
encryption_manager = EncryptionManager()


def encrypt_token(token: str) -> str:
    """Convenience function to encrypt a token."""
    return encryption_manager.encrypt(token)


def decrypt_token(encrypted_token: str) -> str:
    """Convenience function to decrypt a token."""
    return encryption_manager.decrypt(encrypted_token)
