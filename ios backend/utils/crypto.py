import hmac
import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import jwt, JWTError
from config import settings

def compute_hwid_hash(idfv: str, model: str, os_version: str, board_id: str = "") -> str:
    """
    Computes a cryptographic SHA256 hardware identifier from combined device components.
    """
    raw_payload = f"{idfv}::{model}::{os_version}::{board_id}::{settings.SECRET_KEY}"
    return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

def verify_hmac_signature(payload_string: str, provided_signature: str) -> bool:
    """
    Verifies that the incoming request payload was signed using the shared HMAC secret.
    """
    if not provided_signature:
        return False
    
    expected_signature = hmac.new(
        settings.HMAC_SECRET.encode("utf-8"),
        payload_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_signature, provided_signature)

def sign_payload(payload_string: str) -> str:
    """
    Signs a response or request string using the HMAC secret.
    """
    return hmac.new(
        settings.HMAC_SECRET.encode("utf-8"),
        payload_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates a secure signed JWT session token.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow()
    })
    
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Validates and decodes a JWT token.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        return None
