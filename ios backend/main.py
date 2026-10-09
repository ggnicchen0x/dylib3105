import os
import sys
import re
import io
import csv
import time
import math
import hmac
import hashlib
import secrets
import string
import uuid
import logging
import datetime
import warnings
import asyncio
from typing import Optional, Dict, Any, List
from collections import defaultdict
from contextlib import asynccontextmanager

# Suppress python3.12+ datetime deprecation warning noise in terminal
warnings.filterwarnings("ignore", category=DeprecationWarning)

NEPAL_TZ_OFFSET = datetime.timedelta(hours=5, minutes=45)

def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

def is_license_expired(lic) -> bool:
    if not lic:
        return False
    if getattr(lic, "status", None) == "expired":
        return True
    exp = getattr(lic, "expires_at", None)
    if exp is not None and exp <= utc_now():
        return True
    return False

def to_nepal_time(dt: Optional[datetime.datetime]) -> Optional[datetime.datetime]:
    if not dt:
        return None
    return dt + NEPAL_TZ_OFFSET

def format_nepal_time(dt: Optional[datetime.datetime], fmt: str = "%b %d, %Y · %H:%M NPT") -> str:
    if not dt:
        return "—"
    return (dt + NEPAL_TZ_OFFSET).strftime(fmt)

import uvicorn
import httpx
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request, Form, Header, status, Response, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey, delete, text, func, update, desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.future import select
from jose import jwt, JWTError
from passlib.hash import pbkdf2_sha256

# -------------------------------------------------------------
# 1. SETTINGS & CONFIGURATION
# -------------------------------------------------------------
from config import settings, Settings

logger = logging.getLogger("auth_gateway")
logging.basicConfig(level=logging.INFO)

try:
    settings.validate_production_secrets()
except Exception as e:
    logger.warning(f"[SECURITY CONFIG NOTICE] {e}")

# -------------------------------------------------------------
# 2. DATABASE MODELS & ASYNC ENGINE
# -------------------------------------------------------------
Base = declarative_base()

class License(Base):
    __tablename__ = "licenses"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(64), unique=True, index=True, nullable=False)
    status = Column(String(20), default="active", index=True)
    bound_device_hash = Column(String(128), nullable=True, index=True)
    duration_days = Column(Integer, nullable=True, default=None)
    created_at = Column(DateTime, default=utc_now)
    activated_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    notes = Column(String(255), default="Standard User Key")
    
    devices = relationship("Device", back_populates="license", uselist=False)

    @property
    def is_expired(self) -> bool:
        return is_license_expired(self)

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_hash = Column(String(128), unique=True, index=True, nullable=False)
    device_name = Column(String(100), default="Unknown Device")
    device_model = Column(String(64), default="Unknown iOS Device")
    os_version = Column(String(32), default="iOS")
    ip_address = Column(String(64), nullable=True)
    public_key = Column(Text, nullable=True) # Enrolled Secure Enclave public key
    is_banned = Column(Boolean, default=False)
    ban_reason = Column(String(255), nullable=True)
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)
    
    license_id = Column(Integer, ForeignKey("licenses.id"), nullable=True)
    license = relationship("License", back_populates="devices")

class SessionToken(Base):
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), unique=True, index=True, nullable=False)
    device_hash = Column(String(128), index=True, nullable=False)
    license_key = Column(String(64), index=True, nullable=False)
    token = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now)
    last_heartbeat = Column(DateTime, default=utc_now)
    is_revoked = Column(Boolean, default=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=utc_now)
    action = Column(String(64), nullable=False)
    ip_address = Column(String(64), nullable=True)
    device_hash = Column(String(128), nullable=True)
    license_key = Column(String(64), nullable=True)
    details = Column(Text, nullable=True)

class SystemConfig(Base):
    __tablename__ = "system_config"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    app_status = Column(String(20), default="ACTIVE")
    app_version = Column(String(32), default="1.1.3")
    force_update = Column(Boolean, default=False)
    maintenance_message = Column(String(255), default="Server maintenance is currently in progress. Please check Discord announcements for status updates: https://discord.gg/KPJzd42rme")
    release_notes = Column(Text, default="Official Release v1.1.3: Added Visuals (Hologram Location Exposed), Aim Drag, 144 FPS Unlock, Aim Body, and Magic Bullet with ultra-smooth engine performance and dynamic cloud delivery.")
    download_url = Column(String(255), default="https://github.com/nicchen0xf/Swift-ios/releases")
    updated_at = Column(DateTime, default=utc_now)

class PackageRelease(Base):
    __tablename__ = "package_releases"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    release_id = Column(String(64), unique=True, index=True, nullable=False)
    package_name = Column(String(100), index=True, nullable=False)
    filename = Column(String(100), index=True, nullable=False)
    file_sha256 = Column(String(64), index=True, nullable=False)
    file_size = Column(Integer, default=0)
    version_tag = Column(String(32), default="v1.0")
    changed_features = Column(Text, nullable=True)
    release_notes = Column(Text, nullable=False)
    is_published = Column(Boolean, default=True, index=True)
    is_announcement = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=utc_now)
    published_at = Column(DateTime, default=utc_now)

class UserReleaseAcknowledgment(Base):
    __tablename__ = "user_release_acknowledgments"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    release_id = Column(String(64), index=True, nullable=False)
    device_hash = Column(String(128), index=True, nullable=False)
    license_key = Column(String(64), nullable=True, index=True)
    seen_at = Column(DateTime, default=utc_now)

class LicenseActivation(Base):
    __tablename__ = "license_activations"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    activation_id = Column(String(64), unique=True, index=True, nullable=False)
    license_key = Column(String(64), index=True, nullable=False)
    public_key = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    last_verified_at = Column(DateTime, default=utc_now)

from services.release_service import (
    check_package_diff,
    create_and_publish_release,
    get_unseen_releases_for_device,
    record_user_acknowledgment,
    STORAGE_PATCHES_DIR,
    get_latest_release_for_filename,
    normalize_package_name_from_filename
)



engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def init_db():
    async with engine.begin() as conn:
        from sqlalchemy import text
        try:
            await conn.execute(text("PRAGMA journal_mode=WAL;"))
            await conn.execute(text("PRAGMA synchronous=NORMAL;"))
        except Exception:
            pass
        await conn.run_sync(Base.metadata.create_all)
        # Drop unique index on bound_device_hash from older schemas
        try:
            await conn.execute(text("DROP INDEX IF EXISTS ix_licenses_bound_device_hash"))
        except Exception:
            pass
        try:
            await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_licenses_bound_device_hash ON licenses (bound_device_hash)"))
        except Exception:
            pass
        # Automatic SQLite column migration if upgraded from earlier schema
        try:
            await conn.execute(text("ALTER TABLE licenses ADD COLUMN duration_days INTEGER DEFAULT NULL"))
        except Exception:
            pass
        try:
            now_iso = utc_now().strftime("%Y-%m-%d %H:%M:%S")
            await conn.execute(
                text("UPDATE licenses SET status = 'expired' WHERE expires_at IS NOT NULL AND expires_at <= :now AND status = 'active'"),
                {"now": now_iso}
            )
        except Exception:
            pass
        try:
            from sqlalchemy import text
            await conn.execute(text("ALTER TABLE system_config ADD COLUMN release_notes TEXT DEFAULT 'Official Release v1.1.2 with optimized engine performance, enhanced session stability, and dynamic patch delivery.'"))
        except Exception:
            pass
        try:
            from sqlalchemy import text
            await conn.execute(text("ALTER TABLE system_config ADD COLUMN download_url VARCHAR(255) DEFAULT 'https://github.com/nicchen0xf/Swift-ios/releases'"))
        except Exception:
            pass
        try:
            from sqlalchemy import text
            await conn.execute(text("ALTER TABLE system_config ADD COLUMN updated_at DATETIME"))
        except Exception:
            pass
        try:
            from sqlalchemy import text
            await conn.execute(text("DELETE FROM package_releases"))
            await conn.execute(text("DELETE FROM user_release_acknowledgments"))
        except Exception:
            pass

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(SystemConfig))
        config = result.scalars().first()
        if not config:
            config = SystemConfig(
                app_status="ACTIVE",
                app_version="1.1.3",
                force_update=False,
                maintenance_message="Server maintenance is currently in progress. Please check Discord announcements for status updates: https://discord.gg/KPJzd42rme",
                release_notes="Official Release v1.1.3: Added Visuals (Hologram Location Exposed), Aim Drag, 144 FPS Unlock, Aim Body, and Magic Bullet with ultra-smooth engine performance and dynamic cloud delivery.",
                download_url="https://github.com/nicchen0xf/Swift-ios/releases/download/v1.1.3/ByteExternal_V1.1.3.ipa",
                updated_at=utc_now()
            )
            session.add(config)
            await session.commit()
        else:
            # Auto-sync versions to official 1.1.3 release
            if config.app_version in ["4.8.2", "2.1.0", "2.1.1", "2.0.0", "1.1.1", "1.1.2"]:
                config.app_version = "1.1.3"
                config.release_notes = "Official Release v1.1.3: Added Visuals (Hologram Location Exposed), Aim Drag, 144 FPS Unlock, Aim Body, and Magic Bullet with ultra-smooth engine performance and dynamic cloud delivery."
                config.download_url = "https://github.com/nicchen0xf/Swift-ios/releases/download/v1.1.3/ByteExternal_V1.1.3.ipa"
                await session.commit()


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

# -------------------------------------------------------------
# 3. CRYPTOGRAPHIC & SECURITY UTILITIES
# -------------------------------------------------------------
# 3. CRYPTOGRAPHIC & SECURITY UTILITIES
# -------------------------------------------------------------
attempt_history: Dict[str, List[float]] = defaultdict(list)
active_lockouts: Dict[str, float] = {}
seen_signatures: Dict[str, float] = {}
admin_failed_attempts: Dict[str, List[float]] = defaultdict(list)
admin_lockouts: Dict[str, float] = {}
endpoint_history: Dict[str, List[float]] = defaultdict(list)

def bounded_cleanup():
    """Prunes stale state and enforces memory bounds on security tracking dictionaries."""
    now = time.time()
    stale_sig_cutoff = now - 180
    stale_sigs = [k for k, v in seen_signatures.items() if v < stale_sig_cutoff]
    for k in stale_sigs:
        seen_signatures.pop(k, None)
    stale_locks = [k for k, v in active_lockouts.items() if v < now]
    for k in stale_locks:
        active_lockouts.pop(k, None)
        attempt_history.pop(k, None)
    stale_admin_locks = [k for k, v in admin_lockouts.items() if v < now]
    for k in stale_admin_locks:
        admin_lockouts.pop(k, None)
        admin_failed_attempts.pop(k, None)
    # Prune inactive attempt history older than 1 hour to prevent memory creep
    stale_attempts = [k for k, v in list(attempt_history.items()) if not v or (now - max(v)) > 3600]
    for k in stale_attempts:
        attempt_history.pop(k, None)
    # Hard bounds to prevent any memory exhaustion attack
    if len(seen_signatures) > 10000:
        seen_signatures.clear()
    if len(endpoint_history) > 5000:
        endpoint_history.clear()
    if len(attempt_history) > 5000:
        attempt_history.clear()
    if len(active_lockouts) > 5000:
        active_lockouts.clear()

def mask_license_key(key: Optional[str]) -> str:
    """Returns full unmasked license key for display and logging."""
    if not key:
        return "—"
    return str(key).strip()

def hash_admin_password(password: str) -> str:
    """Hashes administrator password using PBKDF2-HMAC-SHA256 with random salt."""
    return pbkdf2_sha256.hash(password)

def verify_admin_credentials(username: str, password: str) -> bool:
    """
    Verifies administrator credentials using PBKDF2-HMAC-SHA256.
    Provides seamless zero-downtime migration for existing SHA-256 password hash.
    """
    user_clean = username.strip()
    user_ok = secrets.compare_digest(user_clean, settings.ADMIN_USER)
    if not user_ok:
        user_hash = hashlib.sha256(user_clean.encode("utf-8")).hexdigest()
        user_ok = secrets.compare_digest(user_hash, settings.ADMIN_USER_HASH)
    
    if not user_ok:
        return False
        
    pass_clean = password.strip()
    # Check if a modern PBKDF2 hash is configured
    if settings.ADMIN_PBKDF2_PASS_HASH:
        try:
            return pbkdf2_sha256.verify(pass_clean, settings.ADMIN_PBKDF2_PASS_HASH)
        except Exception:
            pass
            
    # Check legacy SHA-256 and auto-upgrade
    pass_hash = hashlib.sha256(pass_clean.encode("utf-8")).hexdigest()
    if secrets.compare_digest(pass_hash, settings.ADMIN_PASS_HASH):
        # Auto-upgrade runtime hash to PBKDF2
        settings.ADMIN_PBKDF2_PASS_HASH = hash_admin_password(pass_clean)
        return True
        
    return False

def check_admin_rate_limit(client_ip: str):
    """Enforces brute-force lockout on administrator authentication."""
    now = time.time()
    lockout_expiry = admin_lockouts.get(client_ip)
    if lockout_expiry and now < lockout_expiry:
        remaining = int(math.ceil(lockout_expiry - now))
        mins, secs = remaining // 60, remaining % 60
        time_str = f"{mins}m {secs:02d}s" if mins > 0 else f"{secs}s"
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Admin account locked due to excessive failed attempts. Try again in {time_str}."
        )
    elif lockout_expiry and now >= lockout_expiry:
        admin_lockouts.pop(client_ip, None)
        admin_failed_attempts.pop(client_ip, None)

def record_admin_login_failure(client_ip: str):
    """Records failed admin login attempt and engages 15-minute lockout upon threshold."""
    now = time.time()
    window = now - 300 # 5 minutes window
    history = [t for t in admin_failed_attempts[client_ip] if t > window]
    history.append(now)
    admin_failed_attempts[client_ip] = history
    if len(history) >= settings.ADMIN_MAX_FAILED_ATTEMPTS:
        admin_lockouts[client_ip] = now + settings.ADMIN_LOCKOUT_SECONDS

def clear_admin_login_failures(client_ip: str):
    admin_failed_attempts.pop(client_ip, None)
    admin_lockouts.pop(client_ip, None)

def check_endpoint_rate_limit(key: str, max_requests: int, window_seconds: int = 60):
    """Generic sliding-window rate limiter for sensitive API endpoints."""
    bounded_cleanup()
    now = time.time()
    history = [t for t in endpoint_history[key] if t > now - window_seconds]
    history.append(now)
    endpoint_history[key] = history
    if len(history) > max_requests:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {max_requests} requests per {window_seconds}s."
        )

def get_real_client_ip(request: Request) -> str:
    peer_ip = request.client.host if (request.client and request.client.host) else "127.0.0.1"
    if not getattr(settings, "TRUST_PROXY_HEADERS", True):
        return peer_ip

    trusted = getattr(settings, "TRUSTED_PROXIES", ["127.0.0.1", "::1", "testserver"])
    if peer_ip in trusted or peer_ip in ("127.0.0.1", "::1", "testserver"):
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            return cf_ip.strip()
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            candidate = xff.split(",")[0].strip()
            if candidate:
                return candidate
        x_real = request.headers.get("X-Real-IP")
        if x_real:
            return x_real.strip()
            
    return peer_ip

def check_and_enforce_rate_limit(client_ip: str, device_hash: Optional[str] = None):
    bounded_cleanup()
    now = time.time()
    keys_to_check = [f"ip:{client_ip}"]
    if device_hash:
        keys_to_check.append(f"hwid:{device_hash}")
        
    for key in keys_to_check:
        lockout_expiry = active_lockouts.get(key)
        if lockout_expiry and now < lockout_expiry:
            remaining_seconds = int(math.ceil(lockout_expiry - now))
            minutes = remaining_seconds // 60
            seconds = remaining_seconds % 60
            time_str = f"{minutes}m {seconds:02d}s" if minutes > 0 else f"{seconds}s"
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Spam detected: Do not repeatedly tap login. You have been timed out for 10 minutes. Please wait {time_str} before retrying."
            )
        elif lockout_expiry and now >= lockout_expiry:
            active_lockouts.pop(key, None)
            attempt_history.pop(key, None)

    window_start = now - settings.SPAM_WINDOW_SECONDS
    for key in keys_to_check:
        history = [t for t in attempt_history[key] if t > window_start]
        history.append(now)
        attempt_history[key] = history
        
        if len(history) > settings.SPAM_MAX_ATTEMPTS:
            lockout_until = now + settings.SPAM_LOCKOUT_SECONDS
            for k in keys_to_check:
                active_lockouts[k] = lockout_until
                
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Spam detected: Do not repeatedly tap login. You have been timed out for 10 minutes. Please wait 10m 00s before retrying.",
                headers={"X-New-Lockout": "1"}
            )

def verify_asymmetric_device_signature(public_key_str: str, message_bytes: bytes, signature_str: str) -> bool:
    """
    Cryptographically verifies an ECDSA P-256 (secp256r1) or Ed25519 signature
    generated by the client Secure Enclave or CryptoKit on iOS.
    Supports ASN.1 DER and raw IEEE P1363 (64 bytes: r + s) signatures.
    """
    if not public_key_str or not signature_str:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils as asym_utils
        from cryptography.hazmat.primitives import hashes, serialization
        import base64
        
        sig_clean = signature_str.strip()
        try:
            sig_bytes = bytes.fromhex(sig_clean)
        except ValueError:
            sig_bytes = base64.b64decode(sig_clean)
            
        pk_clean = public_key_str.strip()
        pubkey = None
        if pk_clean.startswith("-----BEGIN"):
            pubkey = serialization.load_pem_public_key(pk_clean.encode('utf-8'))
        else:
            try:
                pk_bytes = bytes.fromhex(pk_clean)
            except ValueError:
                pk_bytes = base64.b64decode(pk_clean)
                
            if len(pk_bytes) in (65, 33) and pk_bytes[0] in (0x02, 0x03, 0x04):
                pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_bytes)
            elif len(pk_bytes) == 32:
                pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)
            else:
                pubkey = serialization.load_der_public_key(pk_bytes)
                
        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            # If 64 bytes, convert raw IEEE P1363 (r, s) into ASN.1 DER format
            if len(sig_bytes) == 64:
                r_int = int.from_bytes(sig_bytes[:32], 'big')
                s_int = int.from_bytes(sig_bytes[32:], 'big')
                sig_der = asym_utils.encode_dss_signature(r_int, s_int)
            else:
                sig_der = sig_bytes
            pubkey.verify(sig_der, message_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        elif isinstance(pubkey, ed25519.Ed25519PublicKey):
            pubkey.verify(sig_bytes, message_bytes)
            return True
        return False
    except Exception as e:
        logger.debug(f"Asymmetric signature verification error: {e}")
        return False

def verify_hmac_signature(payload_string: str, provided_signature: str) -> bool:
    if not provided_signature:
        return False
    expected_signature = hmac.new(
        settings.HMAC_SECRET.encode("utf-8"),
        payload_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_signature, provided_signature)

def sign_payload(payload_string: str) -> str:
    return hmac.new(
        settings.HMAC_SECRET.encode("utf-8"),
        payload_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

def create_access_token(data: Dict[str, Any], expires_delta: Optional[datetime.timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = utc_now() + expires_delta
    else:
        expire = utc_now() + datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": utc_now()})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return None

revoked_admin_tokens = set()

def create_admin_token() -> str:
    expire = utc_now() + datetime.timedelta(hours=24)
    payload = {"sub": "admin", "role": "superadmin", "exp": expire, "jti": str(uuid.uuid4())}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def verify_admin_session(request: Request) -> bool:
    # 1. Bearer Token Authorization
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        if token in revoked_admin_tokens:
            return False
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            return payload.get("sub") == "admin"
        except JWTError:
            return False

    # 2. Legacy x-admin-key header (Restricted, strictly logged)
    header_key = request.headers.get("x-admin-key")
    if header_key:
        if settings.ALLOW_LEGACY_ADMIN_API_KEY and secrets.compare_digest(header_key, settings.ADMIN_API_KEY):
            logger.warning("[SECURITY AUDIT] Legacy x-admin-key header utilized for admin operation.")
            return True
        return False
        
    # 3. HttpOnly Secure Session Cookie
    token = request.cookies.get(settings.ADMIN_SESSION_COOKIE)
    if not token or token in revoked_admin_tokens:
        return False
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload.get("sub") == "admin"
    except JWTError:
        return False

def generate_random_license_key(prefix: str = "BYTE") -> str:
    """
    Format: PREFIX-XXXX-XXXX-XXXX (16 alphanumeric characters)
    """
    clean_prefix = re.sub(r'[^A-Za-z0-9_-]', '', (prefix or "BYTE").strip().upper()) or "BYTE"
    charset = string.ascii_uppercase + string.digits
    parts = [''.join(secrets.choice(charset) for _ in range(4)) for _ in range(3)]
    return f"{clean_prefix}-{'-'.join(parts)}"

def verify_request_integrity(timestamp: int, license_key: str, device_hash: str, signature: str):
    bounded_cleanup()
    current_time = int(time.time())
    
    if abs(current_time - timestamp) > 60:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request timestamp expired or out of synchronization (Anti-Replay Triggered)."
        )
        
    stale_cutoff = current_time - 120
    stale_sigs = [sig for sig, seen in seen_signatures.items() if seen < stale_cutoff]
    for sig in stale_sigs:
        seen_signatures.pop(sig, None)
        
    if signature in seen_signatures:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Duplicate request detected: Signature replay blocked."
        )
        
    payload_to_verify = f"{license_key}:{device_hash}:{timestamp}"
    if not verify_hmac_signature(payload_to_verify, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid cryptographic request signature (HMAC Tamper Triggered)."
        )
        
    seen_signatures[signature] = float(current_time)

# -------------------------------------------------------------
# 4. BUSINESS LOGIC & HARDWARE BINDING
# -------------------------------------------------------------
async def get_or_register_device(
    db: AsyncSession,
    device_hash: str,
    device_name: str,
    device_model: str,
    os_version: str,
    client_ip: str,
    public_key: Optional[str] = None
) -> Device:
    result = await db.execute(select(Device).where(Device.device_hash == device_hash))
    device = result.scalars().first()
    
    if not device:
        device = Device(
            device_hash=device_hash,
            device_name=device_name,
            device_model=device_model,
            os_version=os_version,
            ip_address=client_ip,
            public_key=public_key,
            first_seen=utc_now(),
            last_seen=utc_now()
        )
        db.add(device)
        await db.commit()
        await db.refresh(device)
    else:
        device.last_seen = utc_now()
        device.ip_address = client_ip
        device.device_name = device_name
        if public_key:
            if device.public_key and device.public_key != public_key:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Device public key mismatch. Unauthorized hardware key substitution detected."
                )
            elif not device.public_key:
                device.public_key = public_key
        await db.commit()
        await db.refresh(device)
        
    if device.is_banned:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Device permanently banned: {device.ban_reason or 'Security Violation'}"
        )
    return device

async def activate_or_verify_license(
    db: AsyncSession,
    license_key: str,
    device: Device,
    client_ip: str
) -> License:
    clean_k = license_key.strip().upper()
    result = await db.execute(select(License).where(func.upper(License.key) == clean_k))
    lic = result.scalars().first()
    
    if not lic:
        log = AuditLog(
            action="LOGIN_FAILED_INVALID_KEY",
            ip_address=client_ip,
            device_hash=device.device_hash,
            license_key=license_key,
            details="Attempted login with non-existent license key."
        )
        db.add(log)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid license key provided."
        )
        
    if lic.status == "banned":
        raise HTTPException(status_code=403, detail="License key blacklisted.")
    if lic.status == "revoked":
        raise HTTPException(status_code=403, detail="License key revoked.")
    if is_license_expired(lic):
        lic.status = "expired"
        await db.commit()
        raise HTTPException(status_code=403, detail="License key has expired.")
        
    device_hwid = device.device_hash if hasattr(device, "device_hash") else str(device)
    if lic.bound_device_hash is None:
        lic_id = lic.id
        now = utc_now()

        calc_activated_at = lic.activated_at or now
        calc_expires_at = lic.expires_at
        if calc_expires_at is None and getattr(lic, "duration_days", None) and lic.duration_days > 0:
            calc_expires_at = calc_activated_at + datetime.timedelta(days=lic.duration_days)

        # Atomic Conditional Update: prevents concurrent race conditions on unbound licenses
        try:
            from sqlalchemy import text
            await db.execute(
                text("UPDATE licenses SET bound_device_hash = NULL WHERE bound_device_hash = :hwid AND id != :lic_id"),
                {"hwid": device_hwid, "lic_id": lic_id}
            )
        except Exception:
            pass

        stmt = (
            update(License)
            .where(License.id == lic_id)
            .where(License.bound_device_hash.is_(None))
            .values(
                bound_device_hash=device_hwid,
                activated_at=calc_activated_at,
                expires_at=calc_expires_at,
                status="active"
            )
        )
        update_result = await db.execute(stmt)
        
        if update_result.rowcount == 0:
            # Race condition detected: another concurrent request claimed this license between select and update!
            await db.rollback()
            res_check = await db.execute(select(License).where(License.id == lic_id))
            refreshed_lic = res_check.scalars().first()
            if refreshed_lic and refreshed_lic.bound_device_hash != device_hwid:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="License key is locked to another device. Key sharing is prohibited."
                )
            return refreshed_lic
            
        lic.bound_device_hash = device_hwid
        lic.activated_at = calc_activated_at
        lic.expires_at = calc_expires_at
        lic.status = "active"
        if hasattr(device, "license_id"):
            device.license_id = lic.id
        
        dev_name = getattr(device, "device_name", "Device")
        dev_model = getattr(device, "device_model", "iOS Device")
        
        log = AuditLog(
            action="LICENSE_ACTIVATED",
            ip_address=client_ip,
            device_hash=device_hwid,
            license_key=mask_license_key(license_key),
            details=f"Bound to {dev_name} ({dev_model})"
        )
        db.add(log)
        try:
            await db.commit()
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to commit license activation: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database operation failed. An internal server error occurred."
            )
    else:
        if lic.bound_device_hash != device_hwid:
            log = AuditLog(
                action="HWID_MISMATCH_BLOCKED",
                ip_address=client_ip,
                device_hash=device_hwid,
                license_key=mask_license_key(license_key),
                details="Unauthorized hardware reuse attempt."
            )
            db.add(log)
            await db.commit()
            
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="License key is locked to another device. Key sharing is prohibited."
            )
            
    return lic

# -------------------------------------------------------------
# 5. FASTAPI APPLICATION INITIALIZATION
# -------------------------------------------------------------
async def periodic_license_expiration_worker():
    while True:
        try:
            await asyncio.sleep(60)
            bounded_cleanup()
            async with AsyncSessionLocal() as session:
                from sqlalchemy import text
                await session.execute(
                    text("UPDATE licenses SET status = 'expired' WHERE expires_at IS NOT NULL AND expires_at <= :now AND status = 'active'"),
                    {"now": utc_now().strftime("%Y-%m-%d %H:%M:%S")}
                )
                await session.commit()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug(f"Periodic expiration worker error: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    worker_task = asyncio.create_task(periodic_license_expiration_worker())
    print(f"[*] {settings.APP_NAME} v{settings.VERSION} Database ready on port {settings.PORT}.")
    try:
        yield
    finally:
        worker_task.cancel()
        try:
            await worker_task
        except asyncio.CancelledError:
            pass

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None
)

# Hardened CORS policy: Explicit origins only; no wildcard credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.middleware("http")
async def security_and_tracing_middleware(request: Request, call_next):
    """
    Injects request correlation IDs, enforces payload size caps,
    and sets baseline security headers on every response.
    """
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": "Request payload exceeds maximum allowed size (1 MB limit)."}
        )
        
    req_id = str(uuid.uuid4())[:8]
    request.state.request_id = req_id
    
    response: Response = await call_next(request)
    
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    if request.url.path.startswith("/api/v1/auth/"):
        response.headers["X-API-Deprecation"] = "protocol=v1; status=deprecated; upgrade=/api/v2/auth/login"
        
    if request.url.scheme == "https" or request.headers.get("X-Forwarded-Proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
    return response

# -------------------------------------------------------------
# 6. BYTE SECURE HUB DESIGN SYSTEM & SHELL LAYOUT
# Modern Dark Violet / Obsidian Theme with Manrope & IBM Plex Mono
# -------------------------------------------------------------
PURPLE_EDITORIAL_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700;800;900&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root {
    --bg-base: #050407;
    --bg-sidebar: #060408;
    --bg-surface: #0b0910;
    --bg-surface-elevated: #100d16;
    --bg-surface-hover: #15111e;
    --bg-secondary: #0e0b14;
    
    --border: rgba(255, 255, 255, 0.065);
    --border-subtle: rgba(255, 255, 255, 0.035);
    --border-hover: rgba(139, 92, 246, 0.35);
    --border-focus: #8b5cf6;
    
    --text-primary: #ffffff;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    
    --primary: #8b5cf6;
    --primary-hover: #7c3aed;
    --primary-glow: rgba(139, 92, 246, 0.20);
    
    --success: #10b981;
    --success-bg: rgba(16, 185, 129, 0.10);
    --success-border: rgba(16, 185, 129, 0.20);
    
    --warning: #f59e0b;
    --warning-bg: rgba(245, 158, 11, 0.10);
    --warning-border: rgba(245, 158, 11, 0.20);
    
    --danger: #ef4444;
    --danger-bg: rgba(239, 68, 68, 0.12);
    --danger-border: rgba(239, 68, 68, 0.22);
    
    --radius-sm: 8px;
    --radius-md: 12px;
    --radius-lg: 16px;
    --radius-pill: 9999px;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: 'Manrope', 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
}

body {
    background-color: var(--bg-base);
    color: var(--text-primary);
    min-height: 100dvh;
    overflow-x: hidden;
    background-image: 
        radial-gradient(circle at 75% -5%, rgba(139, 92, 246, 0.06), transparent 45rem),
        linear-gradient(rgba(139, 92, 246, 0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(139, 92, 246, 0.04) 1px, transparent 1px);
    background-size: 100% 100%, 48px 48px, 48px 48px;
    background-attachment: fixed;
}

code, pre, .mono {
    font-family: 'IBM Plex Mono', monospace !important;
}

/* ---------------- Layout & Sidebar ---------------- */
.app-shell {
    display: flex;
    min-height: 100vh;
}

.sidebar {
    width: 260px;
    background: var(--bg-sidebar);
    border-right: 1px solid var(--border);
    position: fixed;
    top: 0;
    bottom: 0;
    left: 0;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    z-index: 50;
}

.sidebar-header {
    height: 76px;
    display: flex;
    align-items: center;
    padding: 0 20px;
    border-bottom: 1px solid var(--border);
    text-decoration: none;
    gap: 12px;
}

.logo-box {
    width: 36px;
    height: 36px;
    background: #8b5cf6;
    color: #ffffff;
    font-weight: 700;
    font-size: 15px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--radius-sm);
    box-shadow: 0 0 16px var(--primary-glow);
    overflow: hidden;
    flex-shrink: 0;
}

.logo-box img {
    width: 100%;
    height: 100%;
    object-fit: cover;
    display: block;
}

.brand-info {
    display: flex;
    flex-direction: column;
}

.brand-title {
    font-size: 13.5px;
    font-weight: 700;
    letter-spacing: 0.04em;
    color: #ffffff;
    text-transform: uppercase;
}

.brand-sub {
    font-size: 9.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.16em;
    color: var(--text-muted);
}

.sidebar-nav {
    padding: 24px 12px;
    flex: 1;
    overflow-y: auto;
}

.nav-section-title {
    font-size: 10.5px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.16em;
    color: var(--text-muted);
    padding: 0 12px;
    margin-bottom: 10px;
}

.nav-item {
    display: flex;
    align-items: center;
    gap: 12px;
    height: 42px;
    padding: 0 14px;
    border-radius: var(--radius-sm);
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 13.5px;
    font-weight: 500;
    transition: all 0.18s ease;
    margin-bottom: 3px;
}

.nav-item:hover {
    color: var(--text-primary);
    background: rgba(255, 255, 255, 0.035);
}

.nav-item.active {
    background: rgba(139, 92, 246, 0.12);
    color: #ffffff;
    font-weight: 600;
    border: 1px solid rgba(139, 92, 246, 0.20);
}

.nav-item.active .nav-icon {
    color: var(--primary);
}

.nav-item.active .nav-dot {
    width: 5px;
    height: 5px;
    border-radius: 50%;
    background: var(--primary);
    margin-left: auto;
    box-shadow: 0 0 8px var(--primary);
}

.nav-icon {
    width: 17px;
    height: 17px;
    display: inline-block;
    flex-shrink: 0;
    color: var(--text-secondary);
}

.sidebar-footer {
    padding: 16px;
    border-top: 1px solid var(--border);
}

.user-card {
    display: flex;
    align-items: center;
    gap: 12px;
    background: var(--bg-surface);
    padding: 10px 12px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    margin-bottom: 8px;
}

.user-avatar {
    width: 34px;
    height: 34px;
    border-radius: 50%;
    background: #1e1338;
    border: 1px solid rgba(139, 92, 246, 0.3);
    color: #c4b5fd;
    font-size: 12px;
    font-weight: 700;
    display: grid;
    place-items: center;
    position: relative;
    flex-shrink: 0;
}

.online-dot {
    position: absolute;
    bottom: 0;
    right: 0;
    width: 8px;
    height: 8px;
    background: var(--success);
    border-radius: 50%;
    border: 2px solid var(--bg-sidebar);
}

.user-name {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
    line-height: 1.2;
}

.user-role {
    font-size: 11px;
    color: var(--text-secondary);
}

.signout-link {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--text-muted);
    text-decoration: none;
    font-size: 12px;
    padding: 6px 8px;
    border-radius: var(--radius-sm);
    transition: color 0.2s ease;
}

.signout-link:hover {
    color: var(--danger);
}

/* ---------------- Main Content & Header ---------------- */
.main-wrapper {
    margin-left: 260px;
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
}

.top-header {
    height: 76px;
    position: sticky;
    top: 0;
    z-index: 40;
    background: rgba(5, 4, 7, 0.90);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border-bottom: 1px solid var(--border);
    padding: 0 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.header-meta {
    display: flex;
    flex-direction: column;
}

.header-breadcrumb {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 10.5px;
    text-transform: uppercase;
    letter-spacing: 0.16em;
    font-weight: 600;
    color: var(--text-muted);
}

.header-title {
    font-size: 20px;
    font-weight: 700;
    color: var(--text-primary);
    margin-top: 2px;
    letter-spacing: -0.01em;
}

.header-actions {
    display: flex;
    align-items: center;
    gap: 12px;
}

.nominal-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    border-radius: var(--radius-pill);
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    color: var(--success);
    font-size: 12px;
    font-weight: 500;
}

.nominal-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--success);
    animation: radarPulse 2s infinite ease-out;
}

.content-container {
    max-width: 1400px;
    width: 100%;
    margin: 0 auto;
    padding: 32px;
}

/* ---------------- Grid & Layout Utilities ---------------- */
.grid-4, .metrics-grid {
    display: grid !important;
    grid-template-columns: repeat(4, minmax(0, 1fr)) !important;
    gap: 16px !important;
    margin-bottom: 24px !important;
}

@media (max-width: 1200px) {
    .grid-4, .metrics-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
    }
}

@media (max-width: 640px) {
    .grid-4, .metrics-grid {
        grid-template-columns: 1fr !important;
    }
}

.dashboard-layout {
    display: grid;
    grid-template-columns: 1.45fr 0.75fr;
    gap: 20px;
    align-items: start;
}

@media (max-width: 1024px) {
    .dashboard-layout {
        grid-template-columns: 1fr;
    }
}

/* ---------------- Activity Rows ---------------- */
.activity-row {
    display: grid;
    grid-template-columns: 80px 145px 1fr;
    gap: 14px;
    align-items: center;
    padding: 13px 20px;
    border-bottom: 1px solid var(--border-subtle);
    font-size: 12px;
}

.activity-row:last-child {
    border-bottom: none;
}

.activity-details {
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 12px;
}

/* ---------------- Panels & Cards (Darker Charcoal Matte) ---------------- */
.panel {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.6);
    overflow: hidden;
}

.panel-header {
    padding: 18px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.panel-body {
    padding: 24px;
}

/* ---------------- Page Intro Component ---------------- */
.page-intro {
    margin-bottom: 28px;
}

.page-intro-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.16em;
    color: var(--primary);
    margin-bottom: 8px;
}

.page-intro-title {
    font-size: 26px;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: #ffffff;
}

.page-intro-text {
    margin-top: 6px;
    font-size: 13.5px;
    color: var(--text-secondary);
    max-width: 680px;
    line-height: 1.6;
}

/* ---------------- Status Badges ---------------- */
.status-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: var(--radius-pill);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.01em;
    white-space: nowrap;
    max-width: fit-content;
}

.status-badge span {
    flex-shrink: 0;
}

.status-success {
    background: var(--success-bg);
    color: var(--success);
    border: 1px solid var(--success-border);
}

.status-warning {
    background: var(--warning-bg);
    color: var(--warning);
    border: 1px solid var(--warning-border);
}

.status-danger {
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid var(--danger-border);
}

.status-violet {
    background: rgba(139, 92, 246, 0.12);
    color: var(--primary);
    border: 1px solid rgba(139, 92, 246, 0.22);
}

/* ---------------- Buttons & Inputs ---------------- */
.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    font-size: 13px;
    font-weight: 600;
    border-radius: var(--radius-sm);
    padding: 9px 18px;
    cursor: pointer;
    text-decoration: none;
    border: none;
    transition: all 0.18s ease;
}

.btn-primary {
    background: #8b5cf6;
    color: #ffffff;
    box-shadow: 0 0 14px var(--primary-glow);
}

.btn-primary:hover {
    background: #7c3aed;
    box-shadow: 0 0 18px rgba(139, 92, 246, 0.35);
    transform: translateY(-1px);
}

.btn-secondary {
    background: var(--bg-surface-elevated);
    color: var(--text-primary);
    border: 1px solid var(--border);
}

.btn-secondary:hover {
    background: var(--bg-surface-hover);
    border-color: rgba(255, 255, 255, 0.12);
}

.btn-ghost {
    background: transparent;
    color: var(--text-secondary);
}

.btn-ghost:hover {
    color: #ffffff;
    background: rgba(255, 255, 255, 0.04);
}

.btn-outline {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
}

.btn-outline:hover {
    color: #ffffff;
    border-color: var(--primary);
}

.btn-danger, .btn-destructive {
    background: #ef4444;
    color: #ffffff;
    box-shadow: 0 0 14px var(--danger-border);
}

.btn-danger:hover, .btn-destructive:hover {
    background: #dc2626;
    box-shadow: 0 0 18px rgba(239, 68, 68, 0.35);
    transform: translateY(-1px);
}

.btn-sm {
    padding: 5px 12px;
    font-size: 12px;
}

.field-label {
    display: block;
    font-size: 12px;
    font-weight: 500;
    color: var(--text-secondary);
    margin-bottom: 6px;
}

.input, .textarea, .select, .form-input,
input[type="text"], input[type="file"], input[type="url"], input[type="password"], textarea, select {
    width: 100%;
    background: #0e0b14 !important;
    border: 1px solid rgba(255, 255, 255, 0.12) !important;
    border-radius: var(--radius-sm) !important;
    padding: 10px 14px !important;
    color: #ffffff !important;
    font-size: 13.5px !important;
    font-family: inherit !important;
    outline: none !important;
    box-sizing: border-box !important;
    transition: border-color 0.18s ease, box-shadow 0.18s ease;
}

.input:focus, .textarea:focus, .select:focus, .form-input:focus,
input[type="text"]:focus, input[type="file"]:focus, input[type="url"]:focus, textarea:focus, select:focus {
    border-color: #8b5cf6 !important;
    box-shadow: 0 0 0 2px rgba(139, 92, 246, 0.25) !important;
}

input[type="file"]::file-selector-button {
    background: #1e1338 !important;
    color: #ffffff !important;
    border: 1px solid rgba(139, 92, 246, 0.4) !important;
    border-radius: 6px !important;
    padding: 6px 14px !important;
    margin-right: 12px !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    cursor: pointer !important;
    transition: background 0.18s ease;
}

input[type="file"]::file-selector-button:hover {
    background: #2a1b4e !important;
    border-color: #8b5cf6 !important;
}

::placeholder {
    color: #64748b !important;
    opacity: 0.85;
}

/* ---------------- Modern Tables ---------------- */
.table-responsive {
    overflow-x: auto;
    width: 100%;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    text-align: left;
}

thead th {
    background: rgba(255, 255, 255, 0.02);
    padding: 12px 18px;
    font-size: 10.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border);
}

tbody td {
    padding: 14px 18px;
    border-bottom: 1px solid var(--border-subtle);
    color: var(--text-primary);
    vertical-align: middle;
}

tbody tr:last-child td {
    border-bottom: none;
}

tbody tr:hover td {
    background: rgba(255, 255, 255, 0.02);
}

/* ---------------- Modals & Dialogs (High Specificity) ---------------- */
.modal-backdrop, .modal-overlay {
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    right: 0 !important;
    bottom: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    background: rgba(3, 2, 5, 0.92) !important;
    backdrop-filter: blur(12px) !important;
    -webkit-backdrop-filter: blur(12px) !important;
    display: none !important;
    align-items: center !important;
    justify-content: center !important;
    z-index: 99999 !important;
    padding: 20px !important;
}

.modal-backdrop.open, .modal-backdrop.active,
.modal-overlay.open, .modal-overlay.active {
    display: flex !important;
}

.modal-card {
    background: #0b0910 !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    width: 100% !important;
    max-width: 480px !important;
    padding: 24px !important;
    box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.95), 0 0 25px rgba(139, 92, 246, 0.15) !important;
    animation: modalSlide 0.22s cubic-bezier(0.16, 1, 0.3, 1) !important;
    position: relative !important;
    z-index: 100000 !important;
}

.modal-title {
    font-size: 18px !important;
    font-weight: 700 !important;
    color: #ffffff !important;
    margin-bottom: 8px !important;
}

.modal-desc {
    font-size: 13px !important;
    color: var(--text-secondary) !important;
    line-height: 1.5 !important;
}

/* Keyframes */
@keyframes radarPulse {
    0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
    70% { box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
    100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}

@keyframes modalSlide {
    from { opacity: 0; transform: scale(0.95) translateY(10px); }
    to { opacity: 1; transform: scale(1) translateY(0); }
}

@keyframes rowFlash {
    0% { background-color: rgba(139, 92, 246, 0.20); }
    100% { background-color: transparent; }
}

.new-row-flash td {
    animation: rowFlash 2s ease-out;
}

/* Alerts */
.alert {
    padding: 14px 18px;
    border-radius: var(--radius-sm);
    font-size: 13.5px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    gap: 10px;
}

.alert-success {
    background: var(--success-bg);
    color: var(--success);
    border: 1px solid var(--success-border);
}

.alert-error {
    background: var(--danger-bg);
    color: var(--danger);
    border: 1px solid var(--danger-border);
}

/* ---------------- Mobile Navigation & Drawer ---------------- */
.mobile-menu-btn {
    display: none;
    align-items: center;
    justify-content: center;
    width: 38px;
    height: 38px;
    border-radius: var(--radius-sm);
    background: var(--bg-surface-elevated);
    border: 1px solid var(--border);
    color: var(--text-primary);
    cursor: pointer;
    flex-shrink: 0;
    transition: all 0.18s ease;
}

.mobile-menu-btn:hover {
    background: var(--bg-surface-hover);
    border-color: rgba(255, 255, 255, 0.12);
    color: #ffffff;
}

.mobile-drawer-overlay {
    position: fixed;
    inset: 0;
    background: rgba(3, 2, 5, 0.82);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    z-index: 99998;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}

.mobile-drawer-overlay.open {
    opacity: 1;
    pointer-events: auto;
}

.mobile-drawer {
    position: fixed;
    top: 0;
    bottom: 0;
    left: 0;
    width: 290px;
    max-width: 86vw;
    background: #08060c;
    border-right: 1px solid var(--border);
    z-index: 99999;
    transform: translateX(-100%);
    transition: transform 0.28s cubic-bezier(0.16, 1, 0.3, 1);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    box-shadow: 20px 0 50px rgba(0, 0, 0, 0.8);
    padding-bottom: env(safe-area-inset-bottom, 16px);
}

.mobile-drawer.open {
    transform: translateX(0);
}

.mobile-drawer-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 18px;
    border-bottom: 1px solid var(--border);
}

.mobile-drawer-close {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-muted);
    cursor: pointer;
    width: 34px;
    height: 34px;
    border-radius: var(--radius-sm);
    display: grid;
    place-items: center;
    transition: all 0.18s ease;
}

.mobile-drawer-close:hover {
    color: #ffffff;
    border-color: rgba(255, 255, 255, 0.15);
    background: rgba(255, 255, 255, 0.04);
}

.version-layout {
    display: grid;
    grid-template-columns: 1fr 340px;
    gap: 24px;
    max-width: 1200px;
    align-items: start;
}

/* ---------------- Responsive Breakpoints ---------------- */
@media (max-width: 900px) {
    .sidebar {
        display: none !important;
    }
    .main-wrapper {
        margin-left: 0 !important;
        width: 100% !important;
        min-width: 0 !important;
    }
    .content-container {
        padding: 20px 16px !important;
    }
    .top-header {
        padding: 0 16px !important;
        height: 68px !important;
        gap: 12px !important;
    }
    .mobile-menu-btn {
        display: inline-flex !important;
    }
    .nominal-badge {
        display: none !important;
    }
    .version-layout {
        grid-template-columns: 1fr !important;
        gap: 20px !important;
    }
}

@media (max-width: 640px) {
    .grid-4, .metrics-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
        gap: 12px !important;
    }
    .dashboard-layout {
        grid-template-columns: 1fr !important;
        gap: 16px !important;
    }
    .top-header {
        height: 62px !important;
    }
    .header-title {
        font-size: 17px !important;
    }
    .header-breadcrumb {
        font-size: 9.5px !important;
    }
    .page-intro-title {
        font-size: 21px !important;
    }
    .page-intro-text {
        font-size: 13px !important;
    }
    .panel {
        border-radius: var(--radius-sm) !important;
    }
    .panel-body {
        padding: 16px !important;
    }
    .panel-header {
        padding: 14px 16px !important;
    }
    .activity-row {
        grid-template-columns: 65px 115px 1fr !important;
        gap: 8px !important;
        padding: 11px 14px !important;
        font-size: 11.5px !important;
    }
    .table-responsive, .panel[style*="overflow-x: auto"] {
        -webkit-overflow-scrolling: touch;
    }
    thead th, tbody td {
        padding: 11px 12px !important;
    }
    .modal-card {
        padding: 20px !important;
        margin: 12px !important;
        max-width: 100% !important;
    }
    .btn {
        padding: 8px 14px !important;
        font-size: 12.5px !important;
    }
}

@media (max-width: 440px) {
    .grid-4, .metrics-grid {
        grid-template-columns: 1fr !important;
    }
    .activity-row {
        display: flex !important;
        flex-direction: column !important;
        align-items: flex-start !important;
        gap: 6px !important;
        padding: 12px 14px !important;
    }
    .activity-details {
        white-space: normal !important;
        word-break: break-word !important;
    }
    .page-intro-title {
        font-size: 19px !important;
    }
}
"""

def render_layout(title: str, eyebrow: str, content: str, active_tab: str = "dashboard", actions: str = "") -> str:
    nav_items = [
        {"to": "/admin/dashboard", "label": "Overview", "icon": """<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/></svg>""", "key": "dashboard"},
        {"to": "/admin/keys", "label": "License keys", "icon": """<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg>""", "key": "keys"},
        {"to": "/admin/releases", "label": "Releases & Patches", "icon": """<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>""", "key": "releases"},
        {"to": "/admin/version", "label": "Version control", "icon": """<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0_1-.963 0z"/></svg>""", "key": "version"},
        {"to": "/admin/status", "label": "App status", "icon": """<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.04"/></svg>""", "key": "status"},
        {"to": "/admin/logs", "label": "Audit logs", "icon": """<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 21h12a2 2 0 0 0 2-2v-2H10v2a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v3h4"/><path d="M19 17V5a2 2 0 0 0-2-2H4"/></svg>""", "key": "logs"},
    ]
    
    nav_links_html = ""
    for item in nav_items:
        is_active = active_tab == item["key"]
        active_class = "active" if is_active else ""
        dot_html = '<span class="nav-dot"></span>' if is_active else ''
        nav_links_html += f"""
        <a href="{item['to']}" class="nav-item {active_class}">
            {item['icon']}
            <span>{item['label']}</span>
            {dot_html}
        </a>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} • BYTE iOS Control Hub</title>
    <style>{PURPLE_EDITORIAL_CSS}</style>
</head>
<body>
    <div class="app-shell">
        <!-- Sidebar Navigation -->
        <aside class="sidebar">
            <div>
                <a href="/admin/dashboard" class="sidebar-header">
                    <div class="logo-box">
                        <img src="/admin/logo.jpg" alt="BYTE OS" onerror="this.style.display='none'; this.parentElement.innerText='B';">
                    </div>
                    <div class="brand-info">
                        <span class="brand-title">BYTE iOS</span>
                        <span class="brand-sub">Control system</span>
                    </div>
                </a>
                <div class="sidebar-nav">
                    <div class="nav-section-title">Command</div>
                    {nav_links_html}
                </div>
            </div>
            
            <div class="sidebar-footer">
                <div class="user-card">
                    <div class="user-avatar">
                        NM
                        <span class="online-dot"></span>
                    </div>
                    <div style="min-width:0; flex:1;">
                        <div class="user-name">Nicchen Moktan</div>
                        <div class="user-role">Super Admin</div>
                    </div>
                </div>
                <a href="/admin/logout" class="signout-link">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>
                    <span>Sign out</span>
                </a>
            </div>
        </aside>
        
        <!-- Mobile Drawer Overlay & Drawer -->
        <div id="mobileDrawerOverlay" class="mobile-drawer-overlay" onclick="closeMobileMenu()"></div>
        <div id="mobileDrawer" class="mobile-drawer">
            <div>
                <div class="mobile-drawer-header">
                    <a href="/admin/dashboard" class="sidebar-header" style="padding: 0; border: none; height: auto;">
                        <div class="logo-box">
                            <img src="/admin/logo.jpg" alt="BYTE OS" onerror="this.style.display='none'; this.parentElement.innerText='B';">
                        </div>
                        <div class="brand-info">
                            <span class="brand-title">BYTE iOS</span>
                            <span class="brand-sub">Control system</span>
                        </div>
                    </a>
                    <button type="button" class="mobile-drawer-close" onclick="closeMobileMenu()" aria-label="Close navigation menu">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                </div>
                <div class="sidebar-nav">
                    <div class="nav-section-title">Command</div>
                    {nav_links_html}
                </div>
            </div>
            
            <div class="sidebar-footer">
                <div class="user-card">
                    <div class="user-avatar">
                        NM
                        <span class="online-dot"></span>
                    </div>
                    <div style="min-width:0; flex:1;">
                        <div class="user-name">Nicchen Moktan</div>
                        <div class="user-role">Super Admin</div>
                    </div>
                </div>
                <a href="/admin/logout" class="signout-link">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>
                    <span>Sign out</span>
                </a>
            </div>
        </div>

        <!-- Main Content Area -->
        <div class="main-wrapper">
            <header class="top-header">
                <div style="display: flex; align-items: center; gap: 14px; min-width: 0;">
                    <button type="button" class="mobile-menu-btn" onclick="openMobileMenu()" aria-label="Open navigation menu">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" x2="20" y1="12" y2="12"/><line x1="4" x2="20" y1="6" y2="6"/><line x1="4" x2="20" y1="18" y2="18"/></svg>
                    </button>
                    <div class="header-meta">
                        <div class="header-breadcrumb">
                            <span>Admin</span>
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 18 6-6-6-6"/></svg>
                            <span>{eyebrow}</span>
                        </div>
                        <h1 class="header-title">{title}</h1>
                    </div>
                </div>
                
                <div class="header-actions">
                    {actions}
                    <div class="nominal-badge">
                        <span class="nominal-dot"></span>
                        <span>All systems nominal</span>
                    </div>
                </div>
            </header>
            
            <main class="content-container">
                {content}
            </main>
        </div>
    </div>
    
    <!-- Global Confirmation Modal -->
    <div id="appConfirmModal" class="modal-backdrop">
        <div class="modal-card" style="max-width: 440px; border: 1px solid rgba(239, 68, 68, 0.28); box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.95), 0 0 35px rgba(239, 68, 68, 0.12);">
            <div style="display: flex; align-items: flex-start; gap: 14px; margin-bottom: 16px;">
                <div id="appConfirmIconContainer" style="width: 42px; height: 42px; border-radius: var(--radius-sm); background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.25); display: flex; align-items: center; justify-content: center; color: #ef4444; flex-shrink: 0;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                </div>
                <div>
                    <h3 id="appConfirmTitle" class="modal-title" style="font-size: 17px; margin-bottom: 4px; color: #ffffff;">Confirm action</h3>
                    <p id="appConfirmDesc" class="modal-desc" style="font-size: 13px; color: var(--text-secondary); line-height: 1.5;">Are you sure you want to proceed with this operation?</p>
                </div>
            </div>
            <form id="appConfirmForm" action="" method="POST" style="margin-top: 20px; display: flex; justify-content: flex-end; gap: 10px;">
                <div id="appConfirmInputs"></div>
                <button type="button" class="btn btn-secondary" onclick="closeModal('appConfirmModal')">Cancel</button>
                <button type="submit" id="appConfirmSubmitBtn" class="btn btn-danger">Confirm</button>
            </form>
        </div>
    </div>

    <script>
    function openMobileMenu() {{
        const drawer = document.getElementById('mobileDrawer');
        const overlay = document.getElementById('mobileDrawerOverlay');
        if (drawer && overlay) {{
            drawer.classList.add('open');
            overlay.classList.add('open');
            document.body.style.overflow = 'hidden';
        }}
    }}
    function closeMobileMenu() {{
        const drawer = document.getElementById('mobileDrawer');
        const overlay = document.getElementById('mobileDrawerOverlay');
        if (drawer && overlay) {{
            drawer.classList.remove('open');
            overlay.classList.remove('open');
            document.body.style.overflow = '';
        }}
    }}
    function openModal(id) {{
        const el = document.getElementById(id);
        if (el) {{
            el.classList.add('open');
            el.style.display = 'flex';
        }}
    }}
    function closeModal(id) {{
        const el = document.getElementById(id);
        if (el) {{
            el.classList.remove('open');
            el.style.display = 'none';
        }}
    }}
    function confirmAction(options) {{
        const modal = document.getElementById('appConfirmModal');
        const titleEl = document.getElementById('appConfirmTitle');
        const descEl = document.getElementById('appConfirmDesc');
        const formEl = document.getElementById('appConfirmForm');
        const submitBtn = document.getElementById('appConfirmSubmitBtn');
        const inputsContainer = document.getElementById('appConfirmInputs');
        const iconContainer = document.getElementById('appConfirmIconContainer');
        
        if (!modal) return false;
        
        titleEl.textContent = options.title || 'Confirm action';
        descEl.textContent = options.desc || 'Are you sure you want to proceed?';
        formEl.action = options.action || '';
        submitBtn.textContent = options.confirmText || 'Confirm';
        
        if (options.variant === 'primary') {{
            submitBtn.className = 'btn btn-primary';
            iconContainer.style.background = 'rgba(139, 92, 246, 0.12)';
            iconContainer.style.borderColor = 'rgba(139, 92, 246, 0.25)';
            iconContainer.style.color = '#a78bfa';
        }} else {{
            submitBtn.className = 'btn btn-danger';
            iconContainer.style.background = 'rgba(239, 68, 68, 0.12)';
            iconContainer.style.borderColor = 'rgba(239, 68, 68, 0.25)';
            iconContainer.style.color = '#ef4444';
        }}
        
        inputsContainer.innerHTML = '';
        if (options.inputs) {{
            for (const [key, value] of Object.entries(options.inputs)) {{
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = key;
                input.value = value;
                inputsContainer.appendChild(input);
            }}
        }}
        
        openModal('appConfirmModal');
        return false;
    }}
    window.addEventListener('click', function(e) {{
        if (e.target && (e.target.classList.contains('modal-backdrop') || e.target.classList.contains('modal-overlay'))) {{
            e.target.classList.remove('open');
            e.target.style.display = 'none';
        }}
    }});
    document.addEventListener('keydown', function(e) {{
        if (e.key === 'Escape') {{
            closeMobileMenu();
            document.querySelectorAll('.modal-backdrop.open, .modal-overlay.open').forEach(el => {{
                el.classList.remove('open');
                el.style.display = 'none';
            }});
        }}
    }});
    </script>
</body>
</html>
"""

# -------------------------------------------------------------
# 7. ADMIN WEB VIEWS (MATCHING EXACT KEYAUTH.CC REFERENCE)
# -------------------------------------------------------------
@app.get("/admin/logo.jpg")
@app.get("/logo.jpg")
async def get_admin_logo():
    candidates = [
        os.path.join(os.path.dirname(__file__), "logo.jpg"),
        os.path.join(os.path.dirname(__file__), "..", "logo.jpg"),
        r"c:\Users\nicch\OneDrive\Desktop\IOS 3105\logo.jpg",
        "logo.jpg",
    ]
    for p in candidates:
        if os.path.exists(p):
            return FileResponse(p, media_type="image/jpeg")
    raise HTTPException(status_code=404, detail="Logo not found")

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request, error: Optional[str] = None):
    if verify_admin_session(request):
        return RedirectResponse(url="/admin/dashboard", status_code=303)
        
    error_html = f'<div class="alert alert-error"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>{error}</div>' if error else ''
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In • BYTE iOS Admin</title>
    <style>
        {PURPLE_EDITORIAL_CSS}
        .login-layout {{
            position: relative;
            display: flex;
            min-height: 100vh;
            background: var(--bg-base);
            overflow: hidden;
        }}
        .grid-bg-overlay {{
            position: absolute;
            inset: 0;
            pointer-events: none;
            background-image: 
                radial-gradient(circle at 75% -5%, rgba(139, 92, 246, 0.06), transparent 45rem),
                linear-gradient(rgba(139, 92, 246, 0.04) 1px, transparent 1px),
                linear-gradient(90deg, rgba(139, 92, 246, 0.04) 1px, transparent 1px);
            background-size: 100% 100%, 48px 48px, 48px 48px;
            opacity: 1;
        }}
        .login-hero {{
            position: relative;
            flex: 1;
            padding: 48px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            border-right: 1px solid var(--border);
            z-index: 10;
        }}
        .login-form-pane {{
            position: relative;
            width: 520px;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 32px;
            z-index: 10;
        }}
        .hero-head-logo {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .hero-center {{
            max-width: 560px;
        }}
        .hero-badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.16em;
            color: var(--primary);
            margin-bottom: 20px;
        }}
        .hero-main-h1 {{
            font-size: 52px;
            font-weight: 600;
            line-height: 1.08;
            letter-spacing: -0.03em;
            color: #ffffff;
        }}
        .hero-main-p {{
            margin-top: 24px;
            font-size: 14px;
            color: var(--text-secondary);
            line-height: 1.75;
            max-width: 440px;
        }}
        .form-box {{
            width: 100%;
            max-width: 384px;
        }}
        .form-kicker {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.16em;
            color: var(--primary);
        }}
        .form-title {{
            font-size: 30px;
            font-weight: 600;
            color: #ffffff;
            margin-top: 12px;
            letter-spacing: -0.02em;
        }}
        .form-subtitle {{
            font-size: 14px;
            color: var(--text-secondary);
            margin-top: 8px;
            margin-bottom: 32px;
        }}
        .pass-wrapper {{
            position: relative;
        }}
        .eye-toggle-btn {{
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 6px;
            display: grid;
            place-items: center;
            border-radius: 4px;
        }}
        .eye-toggle-btn:hover {{
            color: var(--text-primary);
        }}
        .demo-box {{
            margin-top: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 14px;
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            font-size: 12px;
            color: var(--text-secondary);
        }}
        @media (max-width: 960px) {{
            .login-hero {{ display: none; }}
            .login-form-pane {{ width: 100%; }}
        }}
    </style>
</head>
<body>
    <div class="login-layout">
        <!-- Grid pattern overlay -->
        <div class="grid-bg-overlay"></div>
        
        <!-- Left Hero Branding -->
        <div class="login-hero">
            <div class="hero-head-logo">
                <div class="logo-box" style="width: 40px; height: 40px;">
                    <img src="/admin/logo.jpg" alt="BYTE OS" onerror="this.style.display='none'; this.parentElement.innerText='B';">
                </div>
                <div>
                    <p style="font-size: 14px; font-weight: 700; tracking-wide; color: #ffffff; line-height: 1.2;">BYTE iOS</p>
                    <p style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.22em; color: var(--text-muted);">Private infrastructure</p>
                </div>
            </div>
            
            <div class="hero-center">
                <div class="hero-badge">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                    Restricted system
                </div>
                <h1 class="hero-main-h1">Control access.<br>Protect every device.</h1>
                <p class="hero-main-p">A secure command center for license infrastructure, device authorization, and iOS client integrity.</p>
            </div>
            
            <div style="display: flex; align-items: center; gap: 10px; font-size: 12px; color: var(--text-muted);">
                <span style="width: 8px; height: 8px; border-radius: 50%; background: var(--success); flex-shrink: 0;"></span>
                <span>API gateway operational <span style="color: var(--border); margin: 0 4px;">&middot;</span> AES-256 encrypted</span>
            </div>
        </div>
        
        <!-- Right Sign In Form Pane -->
        <div class="login-form-pane">
            <div class="form-box">
                <div class="form-kicker">Administrator access</div>
                <h2 class="form-title">Welcome back</h2>
                <p class="form-subtitle">Authenticate to access the BYTE control system.</p>
                
                {error_html}
                
                <form action="/admin/login" method="POST">
                    <div style="margin-bottom: 20px;">
                        <label class="field-label" style="font-size: 12px; font-weight: 500;">Username</label>
                        <input type="text" name="username" class="input" style="height: 44px; background: #0e0b14;" placeholder="Enter administrator username" required autocomplete="username">
                    </div>
                    
                    <div style="margin-bottom: 28px;">
                        <label class="field-label" style="font-size: 12px; font-weight: 500;">Password</label>
                        <div class="pass-wrapper">
                            <input type="password" id="passInput" name="password" class="input" style="height: 44px; padding-right: 44px; background: #0e0b14;" placeholder="Enter access key" required autocomplete="current-password">
                            <button type="button" class="eye-toggle-btn" onclick="togglePassVisibility()" aria-label="Toggle password visibility">
                                <svg id="eyeIcon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
                            </button>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary" style="width: 100%; height: 44px; font-size: 14px; font-weight: 500;">
                        <span>Enter control panel</span>
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
                    </button>
                </form>
            </div>
        </div>
    </div>
    
    <script>
    function togglePassVisibility() {{
        const input = document.getElementById('passInput');
        const icon = document.getElementById('eyeIcon');
        if (input.type === 'password') {{
            input.type = 'text';
            icon.innerHTML = '<path d="m15 18-.722-3.25"/><path d="M2 8a10.645 10.645 0 0 0 20 0"/><path d="m20 15-1.726-2.05"/><path d="m4 15 1.726-2.05"/><path d="m9 18 .722-3.25"/>';
        }} else {{
            input.type = 'password';
            icon.innerHTML = '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>';
        }}
    }}
    </script>
</body>
</html>
"""
    return HTMLResponse(content=html)

@app.post("/admin/login")
async def admin_login_submit(request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = get_real_client_ip(request)
    is_json = request.headers.get("content-type", "").startswith("application/json") or request.headers.get("accept") == "application/json"
    
    # 1. Enforce Progressive Brute Force Lockout
    try:
        check_admin_rate_limit(client_ip)
    except HTTPException as e:
        if is_json:
            raise e
        return HTMLResponse(
            content=f"<!DOCTYPE html><html><body style='background:#050407;color:#ef4444;font-family:sans-serif;padding:3rem;'><div style='max-width:500px;margin:auto;border:1px solid #ef4444;padding:2rem;border-radius:12px;'><h2>429 Too Many Requests</h2><p>{e.detail}</p><p><a href='/admin/login' style='color:#8b5cf6;'>Return to Login</a></p></div></body></html>",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS
        )

    if is_json:
        try:
            body = await request.json()
            username = str(body.get("username", ""))
            password = str(body.get("password", ""))
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed JSON credentials")
    else:
        form = await request.form()
        username = str(form.get("username", ""))
        password = str(form.get("password", ""))
        
    # 2. Strong PBKDF2 Password Verification with Zero-Downtime Legacy Migration
    is_valid = verify_admin_credentials(username, password)
    
    if is_valid:
        clear_admin_login_failures(client_ip)
        token = create_admin_token()
        
        log = AuditLog(
            action="ADMIN_LOGIN_SUCCESS",
            ip_address=client_ip,
            details=f"Admin session established for '{username.strip()}'."
        )
        db.add(log)
        await db.commit()
        
        if is_json:
            resp = JSONResponse(content={"success": True, "token": token, "message": "Admin session authenticated."})
        else:
            resp = RedirectResponse(url="/admin/dashboard", status_code=303)
            
        resp.set_cookie(
            key=settings.ADMIN_SESSION_COOKIE,
            value=token,
            httponly=True,
            max_age=86400,
            samesite="lax",
            secure=settings.ADMIN_COOKIE_SECURE
        )
        return resp
    else:
        record_admin_login_failure(client_ip)
        log = AuditLog(
            action="ADMIN_LOGIN_FAILED",
            ip_address=client_ip,
            details=f"Failed admin authentication attempt for '{username.strip()}'."
        )
        db.add(log)
        await db.commit()
        if is_json:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin credentials.")
        return RedirectResponse(url="/admin/login?error=Invalid+credentials+provided", status_code=303)

@app.get("/admin/logout")
@app.post("/admin/logout")
async def admin_logout(request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = get_real_client_ip(request)
    
    # Invalidate session token
    auth_header = request.headers.get("authorization")
    token_to_revoke = None
    if auth_header and auth_header.startswith("Bearer "):
        token_to_revoke = auth_header.split(" ", 1)[1].strip()
    else:
        token_to_revoke = request.cookies.get(settings.ADMIN_SESSION_COOKIE)
        
    if token_to_revoke:
        revoked_admin_tokens.add(token_to_revoke)
        
    log = AuditLog(
        action="ADMIN_LOGOUT",
        ip_address=client_ip,
        details="Admin session terminated and token revoked."
    )
    db.add(log)
    try:
        await db.commit()
    except Exception:
        pass
        
    if request.headers.get("accept") == "application/json":
        resp = JSONResponse(content={"success": True, "message": "Admin session revoked."})
    else:
        resp = RedirectResponse(url="/admin/login", status_code=303)
        
    resp.delete_cookie(settings.ADMIN_SESSION_COOKIE)
    return resp

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)

    # Synchronize database statuses for expired licenses
    try:
        now_iso = utc_now().strftime("%Y-%m-%d %H:%M:%S")
        await db.execute(
            text("UPDATE licenses SET status = 'expired' WHERE expires_at IS NOT NULL AND expires_at <= :now AND status = 'active'"),
            {"now": now_iso}
        )
        await db.commit()
    except Exception:
        pass

    res_keys = await db.execute(select(License))
    keys = res_keys.scalars().all()
    
    total_keys = len(keys)
    expired_keys = sum(1 for k in keys if is_license_expired(k) and k.status != "banned")
    active_keys = sum(1 for k in keys if k.bound_device_hash is not None and not is_license_expired(k) and k.status != "banned")
    unused_keys = sum(1 for k in keys if k.bound_device_hash is None and not is_license_expired(k) and k.status != "banned")
    banned_keys = sum(1 for k in keys if k.status == "banned")
    bound_devices = sum(1 for k in keys if k.bound_device_hash is not None and not is_license_expired(k) and k.status != "banned")
    
    utilization = round((active_keys / total_keys * 100)) if total_keys > 0 else 0
    unused_pct = round((unused_keys / total_keys * 100)) if total_keys > 0 else 0
    active_pct = round((active_keys / total_keys * 100)) if total_keys > 0 else 0
    expired_pct = round((expired_keys / total_keys * 100)) if total_keys > 0 else 0
    banned_pct = round((banned_keys / total_keys * 100)) if total_keys > 0 else 0
    
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    app_status = cfg.app_status if cfg else "ACTIVE"
    app_version = cfg.app_version if cfg else "1.1.2"
    force_update = cfg.force_update if cfg else False
    
    is_active = (app_status == "ACTIVE")
    
    # Recent activity logs (5 latest)
    res_logs = await db.execute(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(5))
    recent_logs = res_logs.scalars().all()
    
    def format_action_display(action: str) -> str:
        mapping = {
            "AUTH_SUCCESS": "Auth Success",
            "LOGIN_SUCCESS": "Auth Success",
            "LICENSE_ACTIVATED": "Key Activated",
            "SPAM_RATE_LIMIT_TRIGGERED": "Rate Limited",
            "LOGIN_FAILED_INVALID_KEY": "Invalid Key",
            "HWID_MISMATCH_BLOCKED": "HWID Mismatch",
            "ADMIN_LOGIN_SUCCESS": "Admin Login",
            "ADMIN_LOGIN_FAILED": "Admin Failed",
            "LICENSE_BANNED": "Key Banned",
            "LICENSE_UNBANNED": "Key Unbanned",
            "KILLSWITCH_ENGAGED": "Killswitch On",
            "KILLSWITCH_RESUMED": "Service Resumed",
        }
        return mapping.get(action, action.replace("_", " ").title())
    
    recent_rows_html = ""
    for l in recent_logs:
        tone = "success" if ("SUCCESS" in l.action or "ACTIVATED" in l.action) else ("danger" if ("BANNED" in l.action or "MISMATCH" in l.action or "SPAM" in l.action or "FAILED" in l.action) else "warning")
        time_str = format_nepal_time(l.timestamp, "%H:%M:%S")
        action_label = format_action_display(l.action)
        recent_rows_html += f"""
        <div class="activity-row">
            <span class="mono" style="color: var(--text-secondary); font-size: 12px;">{time_str}</span>
            <div><span class="status-badge status-{tone}"><span style="width:5px; height:5px; border-radius:50%; background:currentColor;"></span>{action_label}</span></div>
            <span class="activity-details">{l.details or '—'}</span>
        </div>
        """
        
    if not recent_rows_html:
        recent_rows_html = '<div style="padding: 36px; text-align: center; color: var(--text-muted); font-size: 13px;">No security events recorded yet.</div>'
        
    status_badge_html = '<span class="status-badge status-success"><span style="width:6px; height:6px; border-radius:50%; background:currentColor;"></span>Active</span>' if is_active else '<span class="status-badge status-warning"><span style="width:6px; height:6px; border-radius:50%; background:currentColor;"></span>Paused</span>'
    status_icon_color = "#10b981" if is_active else "#f59e0b"
    status_action_btn = f"""
    <button type="button" class="btn { 'btn-destructive' if is_active else 'btn-primary' }" style="width: 100%; margin-top: 20px; height: 42px; font-weight: 600;" onclick="openModal('killswitchModal')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>
        <span>{ 'Engage killswitch' if is_active else 'Resume service' }</span>
    </button>
    """
    
    content = f"""
    <div class="page-intro">
        <div class="page-intro-badge">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
            Secure administration
        </div>
        <h2 class="page-intro-title">System at a glance</h2>
        <p class="page-intro-text">Monitor authorization health, client adoption, and recent security events from one place.</p>
    </div>
    
    <!-- Top 4 Metric Cards Grid -->
    <div class="grid-4">
        <div class="panel" style="padding: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <div style="font-size: 13px; color: var(--text-secondary); font-weight: 500;">Total keys</div>
                    <div id="stat-total" style="font-size: 32px; font-weight: 700; letter-spacing: -0.02em; margin-top: 10px; color: #ffffff; line-height: 1;">{total_keys}</div>
                </div>
                <div style="width: 36px; height: 36px; border-radius: 8px; background: rgba(168, 85, 247, 0.12); border: 1px solid rgba(168, 85, 247, 0.24); color: var(--primary); display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 0 16px rgba(168, 85, 247, 0.18);">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>
                </div>
            </div>
            <div style="margin-top: 14px; font-size: 12px; color: var(--text-muted);">+{total_keys} this month</div>
        </div>
        
        <div class="panel" style="padding: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <div style="font-size: 13px; color: var(--text-secondary); font-weight: 500;">Active keys</div>
                    <div id="stat-active" style="font-size: 32px; font-weight: 700; letter-spacing: -0.02em; margin-top: 10px; color: #ffffff; line-height: 1;">{active_keys}</div>
                </div>
                <div style="width: 36px; height: 36px; border-radius: 8px; background: rgba(168, 85, 247, 0.12); border: 1px solid rgba(168, 85, 247, 0.24); color: var(--primary); display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 0 16px rgba(168, 85, 247, 0.18);">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                </div>
            </div>
            <div id="stat-utilization" style="margin-top: 14px; font-size: 12px; color: var(--text-muted);">{utilization}% utilization</div>
        </div>
        
        <div class="panel" style="padding: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <div style="font-size: 13px; color: var(--text-secondary); font-weight: 500;">Bound devices</div>
                    <div id="stat-bound" style="font-size: 32px; font-weight: 700; letter-spacing: -0.02em; margin-top: 10px; color: #ffffff; line-height: 1;">{bound_devices}</div>
                </div>
                <div style="width: 36px; height: 36px; border-radius: 8px; background: rgba(168, 85, 247, 0.12); border: 1px solid rgba(168, 85, 247, 0.24); color: var(--primary); display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 0 16px rgba(168, 85, 247, 0.18);">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="20" x="5" y="2" rx="2" ry="2"/><path d="M12 18h.01"/></svg>
                </div>
            </div>
            <div style="margin-top: 14px; font-size: 12px; color: var(--text-muted);">Verified hardware</div>
        </div>
        
        <div class="panel" style="padding: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <div style="font-size: 13px; color: var(--text-secondary); font-weight: 500;">Client version</div>
                    <div id="stat-ver" class="mono" style="font-size: 28px; font-weight: 700; letter-spacing: -0.02em; margin-top: 10px; color: #ffffff; line-height: 1;">v{app_version}</div>
                </div>
                <div style="width: 36px; height: 36px; border-radius: 8px; background: rgba(168, 85, 247, 0.12); border: 1px solid rgba(168, 85, 247, 0.24); color: var(--primary); display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 0 16px rgba(168, 85, 247, 0.18);">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 1 1 0 10h-2"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
                </div>
            </div>
            <div style="margin-top: 14px; font-size: 12px; color: var(--text-muted);">{ 'Strict match enforced' if force_update else 'Flexible matching' }</div>
        </div>
    </div>
    
    <!-- Two Column Layout -->
    <div class="dashboard-layout">
        <!-- Left: Recent Activity Feed -->
        <div class="panel" style="overflow: hidden;">
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 18px 20px; border-bottom: 1px solid var(--border);">
                <div>
                    <h3 style="font-size: 15px; font-weight: 600; color: #ffffff;">Recent activity</h3>
                    <p style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">Latest authentication and key events</p>
                </div>
                <a href="/admin/logs" class="btn btn-ghost btn-sm" style="color: var(--text-secondary); display: inline-flex; align-items: center; gap: 6px;">
                    <span>View logs</span>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
                </a>
            </div>
            <div>
                {recent_rows_html}
            </div>
        </div>
        
        <!-- Right Column: App Status + Distribution -->
        <div style="display: flex; flex-direction: column; gap: 20px;">
            <!-- Application Status Card -->
            <div class="panel" style="padding: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-size: 13px; color: var(--text-secondary); font-weight: 500;">Application status</div>
                        <div style="margin-top: 8px;">{status_badge_html}</div>
                    </div>
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="{status_icon_color}" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                </div>
                <p style="font-size: 12px; line-height: 1.6; color: var(--text-secondary); margin-top: 18px;">
                    Authentication gateway is { 'accepting client requests normally.' if is_active else 'rejecting all client requests.' }
                </p>
                {status_action_btn}
            </div>
            
            <!-- Key Distribution Card -->
            <div class="panel" style="padding: 20px;">
                <div style="font-size: 13px; color: var(--text-secondary); font-weight: 500;">Key distribution</div>
                <div style="margin-top: 18px; display: flex; height: 8px; overflow: hidden; border-radius: 9999px; background: rgba(255, 255, 255, 0.08);">
                    <span style="width: {unused_pct}%; background: #8b5cf6;" title="Unused: {unused_keys}"></span>
                    <span style="width: {active_pct}%; background: #06b6d4;" title="Active: {active_keys}"></span>
                    <span style="width: {expired_pct}%; background: #f59e0b;" title="Expired: {expired_keys}"></span>
                    <span style="width: {banned_pct}%; background: #ef4444;" title="Banned: {banned_keys}"></span>
                </div>
                <div style="margin-top: 14px; display: grid; grid-template-columns: repeat(4, 1fr); font-size: 11px; color: var(--text-secondary);">
                    <span>Unused {unused_pct}%</span>
                    <span>Active {active_pct}%</span>
                    <span style="color: #f59e0b;">Expired {expired_pct}%</span>
                    <span>Banned {banned_pct}%</span>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Killswitch Confirmation Modal -->
    <div id="killswitchModal" class="modal-backdrop">
        <div class="modal-card">
            <h3 class="modal-title">{ 'Pause all authentication?' if is_active else 'Resume authentication?' }</h3>
            <p class="modal-desc">{ 'All iOS client authorization requests will be rejected immediately.' if is_active else 'Authorized clients will be able to connect again.' }</p>
            <form action="/admin/toggle-status" method="POST" style="margin-top: 24px; display: flex; justify-content: flex-end; gap: 10px;">
                <button type="button" class="btn btn-secondary" onclick="closeModal('killswitchModal')">Cancel</button>
                <button type="submit" class="btn { 'btn-destructive' if is_active else 'btn-primary' }">Confirm change</button>
            </form>
        </div>
    </div>
    """
    return HTMLResponse(content=render_layout("Overview", "Dashboard", content, active_tab="dashboard"))

@app.get("/admin/keys", response_class=HTMLResponse)
async def admin_keys_page(request: Request, msg: Optional[str] = None, new_keys: Optional[str] = None, q: Optional[str] = None, filter: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    # Synchronize database statuses for expired licenses
    try:
        now_iso = utc_now().strftime("%Y-%m-%d %H:%M:%S")
        await db.execute(
            text("UPDATE licenses SET status = 'expired' WHERE expires_at IS NOT NULL AND expires_at <= :now AND status = 'active'"),
            {"now": now_iso}
        )
        await db.commit()
    except Exception:
        pass

    result = await db.execute(select(License).order_by(License.created_at.desc()))
    all_keys = result.scalars().all()
    total_expired_in_db = sum(1 for k in all_keys if is_license_expired(k) and k.status != "banned")
    
    current_filter = filter or "All"
    
    # Filter by search query
    filtered = all_keys
    if q:
        query_str = q.lower().strip()
        filtered = [k for k in filtered if query_str in k.key.lower() or (k.notes and query_str in k.notes.lower()) or (k.bound_device_hash and query_str in k.bound_device_hash.lower())]
        
    # Filter by pill (All, Active, Unused, Expired, Banned)
    if current_filter == "Active":
        filtered = [k for k in filtered if k.status != "banned" and not is_license_expired(k) and k.bound_device_hash is not None]
    elif current_filter == "Unused":
        filtered = [k for k in filtered if k.status != "banned" and not is_license_expired(k) and k.bound_device_hash is None]
    elif current_filter == "Expired":
        filtered = [k for k in filtered if is_license_expired(k) and k.status != "banned"]
    elif current_filter == "Banned":
        filtered = [k for k in filtered if k.status == "banned"]
        
    alert_html = f'<div class="status-badge status-success" style="margin-bottom: 20px; padding: 10px 16px; font-size: 13px;"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>{msg}</div>' if msg else ''
    
    # Generated Keys Results Card with Instant Copy All
    new_keys_banner = ""
    if new_keys:
        raw_list = [k.strip() for k in new_keys.split(",") if k.strip()]
        if raw_list:
            all_keys_multiline = "\\n".join(raw_list)
            key_items_html = ""
            for single_k in raw_list:
                key_items_html += f"""
                <div style="display: flex; align-items: center; justify-content: space-between; background: rgba(255,255,255,0.03); border: 1px solid var(--border); padding: 8px 12px; border-radius: 6px;">
                    <span class="mono" style="font-size: 13px; font-weight: 600; color: #c4b5fd; letter-spacing: 0.05em;">{single_k}</span>
                    <button type="button" class="btn btn-ghost btn-sm" style="padding: 3px 8px; font-size: 11px; gap: 4px;" title="Copy key" onclick="copyKeyText('{single_k}', this)">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
                        <span>Copy</span>
                    </button>
                </div>
                """
            
            new_keys_banner = f"""
            <div class="panel" style="border: 1px solid rgba(139, 92, 246, 0.45); background: linear-gradient(180deg, #130e20 0%, #0c0914 100%); margin-bottom: 24px; padding: 20px; border-radius: var(--radius-md); box-shadow: 0 10px 30px rgba(139, 92, 246, 0.14);">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px; margin-bottom: 16px;">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <div style="width: 36px; height: 36px; border-radius: 8px; background: rgba(139, 92, 246, 0.2); border: 1px solid rgba(139, 92, 246, 0.4); display: grid; place-items: center; color: #c4b5fd;">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                        </div>
                        <div>
                            <div style="font-size: 15px; font-weight: 700; color: #ffffff;">Batch keys created ({len(raw_list)})</div>
                            <div style="font-size: 12px; color: var(--text-secondary);">Keys are active in database. Click below to copy all at once.</div>
                        </div>
                    </div>
                    <button type="button" class="btn btn-primary" style="padding: 9px 20px; font-weight: 600; gap: 8px;" onclick="copyAllKeys('{all_keys_multiline}', this)">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
                        <span>Copy all ({len(raw_list)})</span>
                    </button>
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 10px; max-height: 220px; overflow-y: auto; padding-right: 4px;">
                    {key_items_html}
                </div>
            </div>
            """

    rows_html = ""
    for k in filtered:
        # Determine status display
        if k.status == "banned":
            status_badge = '<span class="status-badge status-danger"><span style="width:5px; height:5px; border-radius:50%; background:currentColor;"></span>Banned</span>'
            status_text = "Banned"
        elif is_license_expired(k):
            status_badge = '<span class="status-badge status-warning" style="background: rgba(245, 158, 11, 0.12); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.28);"><span style="width:5px; height:5px; border-radius:50%; background:currentColor;"></span>Expired</span>'
            status_text = "Expired"
        elif k.bound_device_hash:
            status_badge = '<span class="status-badge status-success"><span style="width:5px; height:5px; border-radius:50%; background:currentColor;"></span>Active</span>'
            status_text = "Active"
        else:
            status_badge = '<span class="status-badge status-violet"><span style="width:5px; height:5px; border-radius:50%; background:currentColor;"></span>Unused</span>'
            status_text = "Unused"
            
        masked_key = k.key
        hwid_display = f"{k.bound_device_hash[:7]}…{k.bound_device_hash[-5:]}" if k.bound_device_hash else "Unbound"
        created_str = format_nepal_time(k.created_at, "%b %d, %Y") if k.created_at else "—"

        if k.status == "banned":
            exp_str = '<span style="color: var(--danger);">Banned</span>'
        elif is_license_expired(k):
            exp_time = format_nepal_time(k.expires_at, "%b %d, %Y") if k.expires_at else "Expired"
            exp_str = f'<span style="color: #f59e0b; font-weight: 500;">Expired ({exp_time})</span>'
        elif k.activated_at and k.expires_at:
            exp_str = f'<span>{format_nepal_time(k.expires_at, "%b %d, %Y")}</span>'
        elif getattr(k, "duration_days", None) and not k.activated_at:
            exp_str = f'<span style="color: #c4b5fd; font-weight: 500;">{k.duration_days} Days (Starts on use)</span>'
        else:
            exp_str = "Lifetime"
            
        notes_str = k.notes or "Admin Issued"
        
        extend_btn = f"""
        <button type="button" class="btn btn-ghost" style="padding: 6px; color: #a78bfa;" title="Extend or Renew validity" onclick="openExtendModal('{k.key}', '{masked_key}')">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        </button>
        """

        ban_unban_btn = f"""
        <form action="/admin/keys/unban" method="POST" style="display:inline;">
            <input type="hidden" name="key" value="{k.key}">
            <button type="submit" class="btn btn-ghost" style="padding: 6px;" title="Unban license">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>
            </button>
        </form>
        """ if k.status == "banned" else f"""
        <form action="/admin/keys/ban" method="POST" style="display:inline;">
            <input type="hidden" name="key" value="{k.key}">
            <button type="submit" class="btn btn-ghost" style="padding: 6px;" title="Ban license">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg>
            </button>
        </form>
        """
        
        reset_btn = f"""
        <button type="button" class="btn btn-ghost" style="padding: 6px;" title="Reset HWID lock" onclick="confirmAction({{ title: 'Reset HWID lock?', desc: 'Unbind hardware identifier for license key {k.key}. The user will be able to bind a new device on their next login.', action: '/admin/keys/reset-hwid', inputs: {{ key: '{k.key}' }}, confirmText: 'Reset HWID', variant: 'primary' }})">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
        </button>
        """ if k.bound_device_hash else f"""
        <button type="button" class="btn btn-ghost" style="padding: 6px; opacity: 0.3; cursor: not-allowed;" title="No hardware bound" disabled>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
        </button>
        """
        
        delete_btn = f"""
        <button type="button" class="btn btn-ghost" style="padding: 6px; color: var(--danger);" title="Delete license" onclick="confirmAction({{ title: 'Delete license key?', desc: 'Permanently delete key {k.key} from the database. Any active iOS sessions associated with this key will be revoked immediately.', action: '/admin/keys/delete', inputs: {{ key: '{k.key}' }}, confirmText: 'Delete key', variant: 'danger' }})">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
        </button>
        """
        
        rows_html += f"""
        <tr style="border-bottom: 1px solid var(--border); transition: background 0.15s ease;" onmouseover="this.style.background='rgba(255,255,255,0.02)'" onmouseout="this.style.background='transparent'">
            <td style="padding: 14px 20px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="mono" style="font-size: 13px; font-weight: 500; color: #ffffff; letter-spacing: 0.04em;">{masked_key}</span>
                    <button type="button" class="btn btn-ghost" style="padding: 4px 6px; color: var(--text-secondary);" title="Copy full license key" onclick="copyKeyText('{k.key}', this)">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
                    </button>
                </div>
            </td>
            <td style="padding: 14px 16px;">{status_badge}</td>
            <td style="padding: 14px 16px;"><span class="mono" style="font-size: 12px; color: var(--text-muted);">{hwid_display}</span></td>
            <td style="padding: 14px 16px; font-size: 12px; color: var(--text-muted);">{created_str}</td>
            <td style="padding: 14px 16px;">
                <div style="font-size: 12px; font-weight: 500;">{exp_str}</div>
                <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px; max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{notes_str}</div>
            </td>
            <td style="padding: 14px 20px; text-align: right;">
                <div style="display: flex; justify-content: flex-end; gap: 4px; align-items: center;">
                    {extend_btn}
                    {ban_unban_btn}
                    {reset_btn}
                    {delete_btn}
                </div>
            </td>
        </tr>
        """
        
    if not rows_html:
        rows_html = '<tr><td colspan="6" style="padding: 48px; text-align: center; color: var(--text-muted); font-size: 13px;">No license keys match this view.</td></tr>'
        
    filter_buttons_html = ""
    for f_opt in ["All", "Active", "Unused", "Expired", "Banned"]:
        btn_class = "btn-secondary" if current_filter == f_opt else "btn-ghost"
        badge = ""
        if f_opt == "Expired" and total_expired_in_db > 0:
            badge = f' <span style="background: rgba(245, 158, 11, 0.2); color: #f59e0b; padding: 1px 7px; border-radius: 10px; font-size: 11px; margin-left: 4px; font-weight: 600;">{total_expired_in_db}</span>'
        filter_buttons_html += f'<a href="/admin/keys?filter={f_opt}&q={q or ""}" class="btn {btn_class} btn-sm">{f_opt}{badge}</a>'
        
    all_table_keys_multiline = "\\n".join([k.key for k in filtered])
    
    delete_expired_btn = ""
    if total_expired_in_db > 0:
        delete_expired_btn = f"""
        <button type="button" class="btn btn-danger" onclick="confirmAction({{ title: 'Delete all expired keys?', desc: 'Permanently remove all {total_expired_in_db} expired license keys from the database. Any sessions associated with these keys will be revoked. This action cannot be undone.', action: '/admin/keys/delete-expired', inputs: {{}}, confirmText: 'Delete all expired', variant: 'danger' }})" title="Permanently delete all {total_expired_in_db} expired keys from the database">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
            <span>Delete expired ({total_expired_in_db})</span>
        </button>
        """
    
    content = f"""
    <div style="display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 20px; margin-bottom: 24px;">
        <div class="page-intro" style="margin-bottom: 0;">
            <div class="page-intro-badge">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                Secure administration
            </div>
            <h2 class="page-intro-title">Key management</h2>
            <p class="page-intro-text">Issue access, monitor device bindings, and respond to compromised licenses.</p>
        </div>
        <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
            {delete_expired_btn}
            <a href="/admin/keys/export?filter={current_filter}&q={q or ''}&format=csv" class="btn btn-secondary" title="Export visible keys as CSV file">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                <span>Export CSV</span>
            </a>
            <button type="button" class="btn btn-secondary" onclick="copyAllKeys('{all_table_keys_multiline}', this)" title="Copy all keys visible in current table">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
                <span>Copy listed ({len(filtered)})</span>
            </button>
            <button type="button" class="btn btn-primary" onclick="openModal('generateModal')">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                <span>Generate keys</span>
            </button>
        </div>
    </div>
    
    {alert_html}
    {new_keys_banner}
    
    <!-- Filter & Search Toolbar -->
    <div class="panel" style="padding: 12px; margin-bottom: 16px; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px;">
        <form action="/admin/keys" method="GET" style="display: flex; align-items: center; gap: 8px; flex: 1; min-width: 260px;">
            <input type="hidden" name="filter" value="{current_filter}">
            <div style="position: relative; width: 100%; max-width: 400px; display: flex; align-items: center;">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" style="position: absolute; left: 14px; top: 50%; transform: translateY(-50%); pointer-events: none; z-index: 2;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <input type="text" name="q" class="input" style="padding-left: 42px !important; height: 38px; font-size: 13px; background: rgba(255, 255, 255, 0.03);" placeholder="Search by key or HWID" value="{q or ''}">
            </div>
        </form>
        <div style="display: flex; gap: 4px; overflow-x: auto;">
            {filter_buttons_html}
        </div>
    </div>
    
    <!-- Keys Table Panel -->
    <div class="panel" style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; text-align: left;">
            <thead style="background: rgba(255, 255, 255, 0.02); border-bottom: 1px solid var(--border); font-size: 10px; text-transform: uppercase; letter-spacing: 0.12em; color: var(--text-muted);">
                <tr>
                    <th style="padding: 14px 20px; font-weight: 600;">License key</th>
                    <th style="padding: 14px 16px; font-weight: 600;">Status</th>
                    <th style="padding: 14px 16px; font-weight: 600;">Device HWID</th>
                    <th style="padding: 14px 16px; font-weight: 600;">Created</th>
                    <th style="padding: 14px 16px; font-weight: 600;">Expiration / note</th>
                    <th style="padding: 14px 20px; text-align: right; font-weight: 600;">Actions</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>
    
    <!-- Generate Keys Modal with 2 Modes (Batch / Custom) -->
    <div id="generateModal" class="modal-backdrop">
        <div class="modal-card" style="max-width: 520px; border-radius: var(--radius-md);">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
                <div>
                    <h3 class="modal-title" style="font-size: 19px; font-weight: 700;">Generate license keys</h3>
                    <p class="modal-desc" style="font-size: 13px; margin-top: 4px;">Issue custom or batch randomized access keys with custom prefixes.</p>
                </div>
                <button type="button" class="btn btn-ghost btn-sm" onclick="closeModal('generateModal')" style="padding: 4px 8px; color: var(--text-muted);" aria-label="Close modal">✕</button>
            </div>

            <!-- Segmented Mode Tabs -->
            <div style="display: flex; background: rgba(255,255,255,0.04); padding: 4px; border-radius: var(--radius-sm); border: 1px solid var(--border); margin-bottom: 20px; gap: 4px;">
                <button type="button" id="tabBatchBtn" class="btn btn-sm" style="flex: 1; border-radius: 6px; background: #8b5cf6; color: #ffffff; font-weight: 600;" onclick="switchGenMode('batch')">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    <span>Batch generator</span>
                </button>
                <button type="button" id="tabCustomBtn" class="btn btn-sm" style="flex: 1; border-radius: 6px; background: transparent; color: var(--text-secondary); font-weight: 500;" onclick="switchGenMode('custom')">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                    <span>Custom keys</span>
                </button>
            </div>

            <form action="/admin/keys/generate" method="POST">
                <input type="hidden" name="gen_mode" id="genModeInput" value="batch">

                <!-- Batch Mode Fields -->
                <div id="batchFields">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 14px;">
                        <div>
                            <label class="field-label" style="display:flex; justify-content:space-between;">
                                <span>Key prefix</span>
                                <span style="font-size: 11px; color: var(--text-muted);">e.g. BYTE</span>
                            </label>
                            <input type="text" name="prefix" class="input mono" value="BYTE" placeholder="BYTE" style="text-transform: uppercase;">
                        </div>
                        <div>
                            <label class="field-label" style="display:flex; justify-content:space-between;">
                                <span>Quantity</span>
                                <span style="font-size: 11px; color: var(--text-muted);">1 - 500</span>
                            </label>
                            <input type="number" name="count" class="input" value="1" min="1" max="500" required>
                        </div>
                    </div>
                </div>

                <!-- Custom Mode Fields -->
                <div id="customFields" style="display: none; margin-bottom: 14px;">
                    <label class="field-label" style="display:flex; justify-content:space-between;">
                        <span>Custom key(s)</span>
                        <span style="font-size: 11px; color: var(--text-muted);">One key per line</span>
                    </label>
                    <textarea name="custom_keys" rows="3" class="textarea mono" style="text-transform: uppercase; font-size: 12.5px;" placeholder="BYTE-VIP-2026&#10;BYTE-SPECIAL-USER-9999"></textarea>
                </div>

                <!-- Shared Settings (Duration & Note) -->
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 22px;">
                    <div>
                        <label class="field-label">Duration</label>
                        <select name="duration" class="input" style="height: 42px;">
                            <option value="1">1 day</option>
                            <option value="3">3 days</option>
                            <option value="7">7 days</option>
                            <option value="14">14 days</option>
                            <option value="30" selected>30 days</option>
                            <option value="60">60 days</option>
                            <option value="90">90 days</option>
                            <option value="365">1 year (365d)</option>
                            <option value="0">Lifetime</option>
                        </select>
                    </div>
                    <div>
                        <label class="field-label">Note or tag</label>
                        <input type="text" name="notes" class="input" placeholder="e.g. reseller key">
                    </div>
                </div>

                <div style="display: flex; justify-content: flex-end; gap: 10px; border-top: 1px solid var(--border); padding-top: 18px;">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('generateModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary" style="padding: 9px 20px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                        <span>Generate keys</span>
                    </button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Extend / Renew Modal -->
    <div id="extendModal" class="modal-backdrop">
        <div class="modal-card" style="max-width: 440px; border-radius: var(--radius-md);">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
                <div>
                    <h3 class="modal-title" style="font-size: 19px; font-weight: 700;">Extend / Renew license</h3>
                    <p class="modal-desc" style="font-size: 13px; margin-top: 4px;">Add validity days or reactivate an expired license key.</p>
                </div>
                <button type="button" class="btn btn-ghost btn-sm" onclick="closeModal('extendModal')" style="padding: 4px 8px; color: var(--text-muted);" aria-label="Close modal">✕</button>
            </div>
            
            <form action="/admin/keys/extend" method="POST">
                <input type="hidden" name="key" id="extendKeyInput">
                
                <div style="margin-bottom: 16px;">
                    <label class="field-label">Target license</label>
                    <div id="extendKeyDisplay" class="mono" style="font-size: 13px; font-weight: 600; color: #c084fc; background: rgba(139, 92, 246, 0.1); border: 1px solid rgba(139, 92, 246, 0.25); padding: 9px 12px; border-radius: 6px; word-break: break-all;"></div>
                </div>

                <div style="margin-bottom: 20px;">
                    <label class="field-label">Add duration</label>
                    <select name="add_days" class="input" style="height: 42px; cursor: pointer;">
                        <option value="1">Add 1 day</option>
                        <option value="3">Add 3 days</option>
                        <option value="7">Add 7 days (1 week)</option>
                        <option value="15">Add 15 days</option>
                        <option value="30" selected>Add 30 days (1 month)</option>
                        <option value="60">Add 60 days (2 months)</option>
                        <option value="90">Add 90 days (3 months)</option>
                        <option value="180">Add 180 days (6 months)</option>
                        <option value="365">Add 365 days (1 year)</option>
                        <option value="0">Convert to lifetime (no expiry)</option>
                    </select>
                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">
                        If expired, duration counts from today. If not yet activated, adds to initial validity.
                    </div>
                </div>

                <div style="display: flex; justify-content: flex-end; gap: 10px; border-top: 1px solid var(--border); padding-top: 18px;">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('extendModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary" style="padding: 9px 20px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                        <span>Apply extension</span>
                    </button>
                </div>
            </form>
        </div>
    </div>
    
    <div id="copyToast" style="position: fixed; bottom: 24px; right: 24px; z-index: 100; background: #14101d; border: 1px solid var(--border); padding: 10px 18px; border-radius: 8px; font-size: 13px; font-weight: 500; display: none; box-shadow: 0 10px 30px rgba(0,0,0,0.8); align-items: center; gap: 8px; color: #ffffff;">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
        <span id="copyToastText">License key copied to clipboard</span>
    </div>
    
    <script>
    function openExtendModal(rawKey, maskedKey) {{
        const input = document.getElementById('extendKeyInput');
        const display = document.getElementById('extendKeyDisplay');
        if (input) input.value = rawKey;
        if (display) display.innerText = maskedKey || rawKey;
        openModal('extendModal');
    }}
    
    function switchGenMode(mode) {{
        const genModeInput = document.getElementById('genModeInput');
        const batchFields = document.getElementById('batchFields');
        const customFields = document.getElementById('customFields');
        const tabBatchBtn = document.getElementById('tabBatchBtn');
        const tabCustomBtn = document.getElementById('tabCustomBtn');
        
        if (mode === 'custom') {{
            genModeInput.value = 'custom';
            batchFields.style.display = 'none';
            customFields.style.display = 'block';
            tabCustomBtn.style.background = '#8b5cf6';
            tabCustomBtn.style.color = '#ffffff';
            tabCustomBtn.style.fontWeight = '600';
            tabBatchBtn.style.background = 'transparent';
            tabBatchBtn.style.color = 'var(--text-secondary)';
            tabBatchBtn.style.fontWeight = '500';
        }} else {{
            genModeInput.value = 'batch';
            batchFields.style.display = 'block';
            customFields.style.display = 'none';
            tabBatchBtn.style.background = '#8b5cf6';
            tabBatchBtn.style.color = '#ffffff';
            tabBatchBtn.style.fontWeight = '600';
            tabCustomBtn.style.background = 'transparent';
            tabCustomBtn.style.color = 'var(--text-secondary)';
            tabCustomBtn.style.fontWeight = '500';
        }}
    }}
    
    function copyKeyText(text, btn) {{
        if (!text) return;
        if (navigator.clipboard && window.isSecureContext) {{
            navigator.clipboard.writeText(text).then(() => {{
                handleCopySuccess(btn, 'License key copied');
            }}).catch(() => {{
                fallbackCopy(text, btn, 'License key copied');
            }});
        }} else {{
            fallbackCopy(text, btn, 'License key copied');
        }}
    }}
    
    function copyAllKeys(text, btn) {{
        if (!text) return;
        const normalizedText = text.replace(/\\\\n/g, '\\n');
        if (navigator.clipboard && window.isSecureContext) {{
            navigator.clipboard.writeText(normalizedText).then(() => {{
                handleCopySuccess(btn, 'All keys copied to clipboard');
            }}).catch(() => {{
                fallbackCopy(normalizedText, btn, 'All keys copied to clipboard');
            }});
        }} else {{
            fallbackCopy(normalizedText, btn, 'All keys copied to clipboard');
        }}
    }}
    
    function fallbackCopy(text, btn, msg) {{
        try {{
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.top = '0';
            textArea.style.left = '0';
            textArea.style.width = '2em';
            textArea.style.height = '2em';
            textArea.style.padding = '0';
            textArea.style.border = 'none';
            textArea.style.outline = 'none';
            textArea.style.boxShadow = 'none';
            textArea.style.background = 'transparent';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            const successful = document.execCommand('copy');
            document.body.removeChild(textArea);
            if (successful) {{
                handleCopySuccess(btn, msg);
            }} else {{
                prompt('Copy keys:', text);
            }}
        }} catch (err) {{
            prompt('Copy keys:', text);
        }}
    }}
    
    function handleCopySuccess(btn, msg) {{
        showCopyToast(msg);
        if (btn) {{
            const origHtml = btn.innerHTML;
            const origColor = btn.style.color;
            btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg><span>Copied!</span>';
            btn.style.color = '#10b981';
            setTimeout(() => {{
                btn.innerHTML = origHtml;
                btn.style.color = origColor;
            }}, 1800);
        }}
    }}
    
    function showCopyToast(msg) {{
        const toast = document.getElementById('copyToast');
        const textSpan = document.getElementById('copyToastText');
        if (toast) {{
            if (msg && textSpan) textSpan.innerText = msg;
            toast.style.display = 'flex';
            setTimeout(() => {{ toast.style.display = 'none'; }}, 2200);
        }}
    }}
    </script>
    """
    return HTMLResponse(content=render_layout("License keys", "Access", content, active_tab="keys"))

@app.post("/admin/keys/generate")
async def admin_generate_keys_submit(
    request: Request,
    gen_mode: str = Form("batch"),
    prefix: str = Form("BYTE"),
    count: int = Form(1),
    custom_keys: str = Form(""),
    duration: int = Form(0),
    notes: str = Form(""),
    db: AsyncSession = Depends(get_db)
):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    duration_days = duration if duration > 0 else None
    clean_prefix = re.sub(r'[^A-Za-z0-9_-]', '', (prefix or "BYTE").strip().upper()) or "BYTE"
    note_text = notes.strip() or "Admin Generated"
    
    created = []
    
    if gen_mode == "custom" and custom_keys.strip():
        raw_lines = [line.strip().upper() for line in custom_keys.splitlines() if line.strip()]
        for k in raw_lines:
            existing = await db.execute(select(License).where(License.key == k))
            if not existing.scalars().first():
                lic = License(
                    key=k,
                    status="active",
                    bound_device_hash=None,
                    duration_days=duration_days,
                    created_at=utc_now(),
                    activated_at=None,
                    expires_at=None,
                    notes=note_text
                )
                db.add(lic)
                created.append(k)
    else:
        actual_count = max(1, min(count, 500))
        for _ in range(actual_count):
            k = generate_random_license_key(prefix=clean_prefix)
            lic = License(
                key=k,
                status="active",
                bound_device_hash=None,
                duration_days=duration_days,
                created_at=utc_now(),
                activated_at=None,
                expires_at=None,
                notes=note_text
            )
            db.add(lic)
            created.append(k)
            
    await db.commit()
    
    if not created:
        return RedirectResponse(url="/admin/keys?msg=No+new+keys+created+(duplicate+keys+or+empty+input).", status_code=303)
        
    new_keys_param = ",".join(created)
    return RedirectResponse(url=f"/admin/keys?msg=Successfully+generated+{len(created)}+license+key(s).&new_keys={new_keys_param}", status_code=303)

@app.post("/admin/keys/ban")
async def admin_ban_key(request: Request, key: str = Form(...), db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    result = await db.execute(select(License).where(License.key == key))
    lic = result.scalars().first()
    if lic:
        lic.status = "banned"
        await db.commit()
    return RedirectResponse(url="/admin/keys?msg=License+banned+successfully.", status_code=303)

@app.post("/admin/keys/unban")
async def admin_unban_key(request: Request, key: str = Form(...), db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    result = await db.execute(select(License).where(License.key == key))
    lic = result.scalars().first()
    if lic:
        lic.status = "expired" if is_license_expired(lic) else "active"
        await db.commit()
    return RedirectResponse(url="/admin/keys?msg=License+unbanned+successfully.", status_code=303)

@app.post("/admin/keys/reset-hwid")
async def admin_reset_hwid_key(request: Request, key: str = Form(...), db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    result = await db.execute(select(License).where(License.key == key))
    lic = result.scalars().first()
    if lic:
        lic.bound_device_hash = None
        if lic.status != "banned" and not is_license_expired(lic):
            lic.status = "active"
        await db.commit()
    return RedirectResponse(url="/admin/keys?msg=Device+binding+reset.", status_code=303)

@app.post("/admin/keys/delete")
async def admin_delete_key(request: Request, key: str = Form(...), db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    result = await db.execute(select(License).where(License.key == key))
    lic = result.scalars().first()
    if lic:
        await db.delete(lic)
        await db.commit()
    return RedirectResponse(url="/admin/keys?msg=License+key+deleted.", status_code=303)

@app.post("/admin/keys/delete-expired")
async def admin_delete_expired_keys(request: Request, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    res = await db.execute(select(License))
    all_keys = res.scalars().all()
    expired_keys = [k for k in all_keys if is_license_expired(k) and k.status != "banned"]
    
    deleted_count = len(expired_keys)
    if deleted_count > 0:
        expired_key_strings = [k.key for k in expired_keys]
        try:
            from sqlalchemy import update
            await db.execute(
                update(SessionToken)
                .where(SessionToken.license_key.in_(expired_key_strings))
                .values(is_revoked=True)
            )
        except Exception:
            pass
            
        for k in expired_keys:
            await db.delete(k)
            
        log = AuditLog(
            action="ADMIN_DELETE_EXPIRED_KEYS",
            ip_address=get_real_client_ip(request),
            details=f"Admin bulk-deleted {deleted_count} expired license keys from database."
        )
        db.add(log)
        await db.commit()
        msg = f"Successfully+deleted+{deleted_count}+expired+license+key(s)+from+database."
    else:
        msg = "No+expired+license+keys+found+to+delete."
        
    return RedirectResponse(url=f"/admin/keys?filter=Expired&msg={msg}", status_code=303)

@app.post("/admin/keys/extend")
async def admin_extend_key(
    request: Request,
    key: str = Form(...),
    add_days: int = Form(30),
    db: AsyncSession = Depends(get_db)
):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    result = await db.execute(select(License).where(License.key == key))
    lic = result.scalars().first()
    if not lic:
        return RedirectResponse(url="/admin/keys?msg=License+key+not+found.", status_code=303)
        
    now = utc_now()
    if add_days == 0:
        lic.expires_at = None
        lic.duration_days = None
        if lic.status == "expired":
            lic.status = "active"
        msg = f"License+{key}+converted+to+Lifetime+(No+Expiry)."
    else:
        if is_license_expired(lic):
            lic.expires_at = now + datetime.timedelta(days=add_days)
            lic.status = "active"
            msg = f"License+{key}+renewed+for+{add_days}+days+starting+now."
        elif lic.activated_at is None:
            current_duration = lic.duration_days or 0
            lic.duration_days = current_duration + add_days
            msg = f"License+{key}+initial+duration+extended+by+{add_days}+days+(total+{lic.duration_days}+days)."
        else:
            base_time = lic.expires_at if lic.expires_at and lic.expires_at > now else now
            lic.expires_at = base_time + datetime.timedelta(days=add_days)
            lic.status = "active"
            msg = f"License+{key}+validity+extended+by+{add_days}+days."

    await db.commit()
    return RedirectResponse(url=f"/admin/keys?msg={msg}", status_code=303)

@app.get("/admin/keys/export")
async def admin_export_keys(
    request: Request,
    filter: str = "All",
    q: Optional[str] = None,
    format: str = "csv",
    db: AsyncSession = Depends(get_db)
):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    query = select(License).order_by(License.created_at.desc())
    res = await db.execute(query)
    all_keys = res.scalars().all()
    
    filtered = []
    for k in all_keys:
        expired = is_license_expired(k)
        if filter == "Active" and (k.status != "active" or expired or k.bound_device_hash is None):
            continue
        elif filter == "Unused" and (k.status != "active" or expired or k.bound_device_hash is not None):
            continue
        elif filter == "Expired" and not expired:
            continue
        elif filter == "Banned" and k.status != "banned":
            continue
            
        if q:
            match_key = q.lower() in (k.key or "").lower()
            match_hwid = q.lower() in (k.bound_device_hash or "").lower()
            if not (match_key or match_hwid):
                continue
                
        filtered.append(k)

    timestamp = utc_now().strftime("%Y%m%d_%H%M%S")
    
    if format == "txt":
        txt_content = "\n".join([k.key for k in filtered])
        return Response(
            content=txt_content,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="licenses_{filter.lower()}_{timestamp}.txt"'}
        )
    else:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Key", "Status", "Bound HWID", "Duration Days", "Created At", "Activated At", "Expires At", "Notes"])
        for k in filtered:
            status_text = "expired" if is_license_expired(k) and k.status != "banned" else k.status
            writer.writerow([
                k.key,
                status_text,
                k.bound_device_hash or "",
                k.duration_days if k.duration_days is not None else "Lifetime",
                k.created_at.strftime("%Y-%m-%d %H:%M:%S") if k.created_at else "",
                k.activated_at.strftime("%Y-%m-%d %H:%M:%S") if k.activated_at else "Never",
                k.expires_at.strftime("%Y-%m-%d %H:%M:%S") if k.expires_at else "Never / Lifetime",
                k.notes or ""
            ])
        csv_data = output.getvalue()
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="licenses_{filter.lower()}_{timestamp}.csv"'}
        )

@app.get("/admin/version", response_class=HTMLResponse)
async def admin_version_page(request: Request, msg: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    current_ver = cfg.app_version if cfg else "1.1.2"
    force_update = cfg.force_update if cfg else False
    download_url_val = cfg.download_url if (cfg and cfg.download_url) else "https://github.com/nicchen0xf/Swift-ios/releases"
    notes_val = cfg.release_notes if cfg and cfg.release_notes else "Official Release v1.1.2: Added Visuals (Hologram Location Exposed), Aim Drag, 144 FPS Unlock, Aim Body, and Magic Bullet with ultra-smooth engine performance and dynamic cloud delivery."
    updated_str = format_nepal_time(cfg.updated_at, "%b %d, %Y · %H:%M NPT") if (cfg and cfg.updated_at) else "Just now"
    
    alert_html = f'<div class="status-badge status-success" style="margin-bottom: 20px; padding: 10px 16px; font-size: 13px;">{msg}</div>' if msg else ''
    
    content = f"""
    <div class="page-intro">
        <div class="page-intro-badge">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
            Secure administration
        </div>
        <h2 class="page-intro-title">iOS client requirements</h2>
        <p class="page-intro-text">Define the minimum supported release and communicate important guidance to every client.</p>
    </div>
    
    {alert_html}
    
    <div class="version-layout">
        <!-- Main Form Panel -->
        <section class="panel" style="padding: 24px;">
            <form action="/admin/version" method="POST">
                <div style="display: flex; flex-direction: column; gap: 24px;">
                    <div>
                        <label class="field-label">Minimum required version</label>
                        <input type="text" name="app_version" class="input mono" style="max-width: 240px; font-weight: 600;" value="{current_ver}" required placeholder="1.1.2">
                    </div>
                    
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 20px; padding: 20px 0; border-top: 1px solid var(--border); border-bottom: 1px solid var(--border);">
                        <div>
                            <div style="font-size: 14px; font-weight: 500;">Force update</div>
                            <div style="font-size: 12px; color: var(--text-muted); line-height: 1.5; margin-top: 2px;">Reject authentication from clients that do not exactly match the required version.</div>
                        </div>
                        <label style="position: relative; display: inline-block; width: 44px; height: 24px; flex-shrink: 0; cursor: pointer;">
                            <input type="checkbox" name="force_update" value="true" {'checked' if force_update else ''} style="opacity: 0; width: 0; height: 0;" id="forceToggle" onchange="this.nextElementSibling.style.background = this.checked ? 'var(--primary)' : 'rgba(255,255,255,0.12)'; this.nextElementSibling.firstElementChild.style.transform = this.checked ? 'translateX(20px)' : 'translateX(0px)';">
                            <span style="position: absolute; cursor: pointer; inset: 0; background: {'var(--primary)' if force_update else 'rgba(255,255,255,0.12)'}; border-radius: 9999px; transition: 0.2s ease;">
                                <span style="position: absolute; height: 18px; width: 18px; left: 3px; bottom: 3px; background: white; border-radius: 50%; transition: 0.2s ease; transform: {'translateX(20px)' if force_update else 'translateX(0px)'};"></span>
                            </span>
                        </label>
                    </div>

                    <div>
                        <label class="field-label">GitHub release / Download URL</label>
                        <input type="url" name="download_url" class="input" style="font-family: inherit; font-size: 13px;" value="{download_url_val}" required placeholder="https://github.com/nicchennnnn/External/releases">
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 5px;">Users will be redirected to this URL when tapping OK / Update on their iOS device.</div>
                    </div>
                    
                    <div>
                        <label class="field-label">Release notes / advisory (Shown on iOS Update Alert)</label>
                        <textarea name="release_notes" rows="6" class="input" style="resize: none; font-family: inherit; line-height: 1.6;" placeholder="Security advisory or version changelog...">{notes_val}</textarea>
                    </div>
                    
                    <div style="display: flex; justify-content: flex-end;">
                        <button type="submit" class="btn btn-primary">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                            Save policy
                        </button>
                    </div>
                </div>
            </form>
        </section>
        
        <!-- Right Sidebar Info -->
        <aside style="display: flex; flex-direction: column; gap: 20px;">
            <div class="panel" style="padding: 20px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
                <h3 style="margin-top: 14px; font-size: 15px; font-weight: 600;">Current policy</h3>
                <p style="margin-top: 8px; font-size: 13px; color: var(--text-muted); line-height: 1.5;">
                    Version <span class="mono" style="color: var(--text-primary); font-weight: 600;">v{current_ver}</span> is currently required.
                </p>
                <div style="margin-top: 16px; display: flex; align-items: center; gap: 8px; font-size: 11px; color: var(--text-muted);">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                    <span>{updated_str}</span>
                </div>
            </div>
            
            <div class="panel" style="padding: 20px; border: 1px solid rgba(245, 158, 11, 0.25);">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--warning)" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <p style="margin-top: 12px; font-size: 13px; font-weight: 600; color: var(--warning);">Compatibility warning</p>
                <p style="margin-top: 6px; font-size: 12px; line-height: 1.6; color: var(--text-muted);">
                    Forced updates immediately lock out older clients. Confirm the release is uploaded to GitHub first.
                </p>
            </div>
        </aside>
    </div>
    """
    return HTMLResponse(content=render_layout("Version control", "Client policy", content, active_tab="version"))

@app.post("/admin/version")
async def admin_version_submit(request: Request, app_version: str = Form(...), force_update: bool = Form(False), download_url: str = Form("https://github.com/nicchennnnn/External/releases"), release_notes: str = Form(""), db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    if not cfg:
        cfg = SystemConfig(app_version=app_version, force_update=force_update, download_url=download_url, release_notes=release_notes, updated_at=utc_now())
        db.add(cfg)
    else:
        cfg.app_version = app_version
        cfg.force_update = force_update
        cfg.download_url = download_url
        cfg.release_notes = release_notes
        cfg.updated_at = utc_now()
    await db.commit()
    return RedirectResponse(url="/admin/version?msg=Version+policy+saved.", status_code=303)

@app.get("/admin/status", response_class=HTMLResponse)
async def admin_status_page(request: Request, msg: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    app_status = cfg.app_status if cfg else "ACTIVE"
    maint_msg = cfg.maintenance_message if cfg else "Server maintenance is currently in progress. Please check Discord announcements for status updates."
    is_active = (app_status == "ACTIVE")
    
    alert_html = f'<div class="status-badge status-success" style="margin-bottom: 20px; padding: 10px 16px; font-size: 13px;">{msg}</div>' if msg else ''
    border_color = "var(--success)" if is_active else "var(--warning)"
    
    content = f"""
    <div class="page-intro">
        <div class="page-intro-badge">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
            Secure administration
        </div>
        <h2 class="page-intro-title">Service availability</h2>
        <p class="page-intro-text">Pause authentication globally and set the exact message shown to iOS client users.</p>
    </div>
    
    {alert_html}
    
    <!-- Global Status Banner Card -->
    <div class="panel" style="margin-bottom: 24px; overflow: hidden; border-left: 3px solid {border_color};">
        <div style="padding: 24px; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 20px;">
            <div style="display: flex; align-items: center; gap: 18px;">
                <div style="width: 48px; height: 48px; border-radius: 8px; background: {'rgba(34, 197, 94, 0.12)' if is_active else 'rgba(245, 158, 11, 0.12)'}; color: {border_color}; display: flex; align-items: center; justify-content: center;">
                    { '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/></svg>' if is_active else '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="10" y1="15" x2="10" y2="9"/><line x1="14" y1="15" x2="14" y2="9"/></svg>' }
                </div>
                <div>
                    <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.14em; color: var(--text-muted); font-weight: 600;">Global state</div>
                    <h3 style="font-size: 22px; font-weight: 700; letter-spacing: -0.01em; margin-top: 4px;">{ 'Authentication active' if is_active else 'Authentication paused' }</h3>
                    <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">{ 'Clients are being authenticated normally.' if is_active else 'All client authentication requests are being denied.' }</p>
                </div>
            </div>
            
            <button type="button" class="btn { 'btn-destructive' if is_active else 'btn-primary' }" onclick="openModal('killswitchStatusModal')">
                { '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="10" y1="15" x2="10" y2="9"/><line x1="14" y1="15" x2="14" y2="9"/></svg>' if is_active else '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/></svg>' }
                { 'Engage killswitch' if is_active else 'Resume service' }
            </button>
        </div>
    </div>
    
    <!-- Maintenance Message Panel -->
    <section class="panel" style="padding: 24px; max-width: 900px;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
            <div style="width: 32px; height: 32px; border-radius: 6px; background: rgba(168, 85, 247, 0.12); color: var(--primary); display: flex; align-items: center; justify-content: center;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/></svg>
            </div>
            <div>
                <h3 style="font-size: 15px; font-weight: 600;">Maintenance message</h3>
                <p style="font-size: 12px; color: var(--text-muted); margin-top: 1px;">Displayed when authentication is paused.</p>
            </div>
        </div>
        
        <form action="/admin/status" method="POST">
            <input type="hidden" name="app_status" value="{app_status}">
            <textarea rows="6" name="maintenance_message" class="input" style="resize: none; font-family: inherit; line-height: 1.6;" placeholder="Custom maintenance message for iOS popup...">{maint_msg}</textarea>
            <div style="display: flex; justify-content: flex-end; margin-top: 16px;">
                <button type="submit" class="btn btn-primary">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                    Save message
                </button>
            </div>
        </form>
    </section>
    
    <!-- Killswitch Modal -->
    <div id="killswitchStatusModal" class="modal-backdrop">
        <div class="modal-card">
            <h3 class="modal-title">{ 'Engage the global killswitch?' if is_active else 'Resume client authentication?' }</h3>
            <p class="modal-desc">{ 'This immediately blocks every BYTE iOS client, including currently active licenses.' if is_active else 'Clients with valid licenses will regain access immediately.' }</p>
            <form action="/admin/status/toggle" method="POST" style="margin-top: 24px; display: flex; justify-content: flex-end; gap: 10px;">
                <button type="button" class="btn btn-secondary" onclick="closeModal('killswitchStatusModal')">Cancel</button>
                <button type="submit" class="btn { 'btn-destructive' if is_active else 'btn-primary' }">Confirm status change</button>
            </form>
        </div>
    </div>
    """
    return HTMLResponse(content=render_layout("App status", "Killswitch", content, active_tab="status"))

@app.post("/admin/status")
async def admin_status_submit(request: Request, app_status: str = Form("ACTIVE"), maintenance_message: str = Form(...), db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    if cfg:
        cfg.maintenance_message = maintenance_message
        await db.commit()
    return RedirectResponse(url="/admin/status?msg=Maintenance+message+saved.", status_code=303)

@app.post("/admin/status/toggle")
async def admin_status_toggle(request: Request, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    if cfg:
        new_status = "PAUSED" if cfg.app_status == "ACTIVE" else "ACTIVE"
        cfg.app_status = new_status
        await db.commit()
        msg = "Killswitch+engaged." if new_status == "PAUSED" else "Authentication+resumed."
        return RedirectResponse(url=f"/admin/status?msg={msg}", status_code=303)
    return RedirectResponse(url="/admin/status", status_code=303)

@app.post("/admin/toggle-status")
async def admin_toggle_status_quick(request: Request, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    if cfg:
        cfg.app_status = "PAUSED" if cfg.app_status == "ACTIVE" else "ACTIVE"
        await db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=303)

@app.get("/admin/logs", response_class=HTMLResponse)
async def admin_logs_page(request: Request, msg: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    result = await db.execute(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100))
    logs = result.scalars().all()
    
    alert_html = f'<div class="status-badge status-success" style="margin-bottom: 20px; padding: 10px 16px; font-size: 13px;"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>{msg}</div>' if msg else ''
    
    rows_html = ""
    for l in logs:
        tone = "success" if ("SUCCESS" in l.action or "ACTIVATED" in l.action) else ("danger" if ("BANNED" in l.action or "MISMATCH" in l.action or "SPAM" in l.action) else "warning")
        time_str = format_nepal_time(l.timestamp, "%Y-%m-%d %H:%M:%S")
        ip_str = l.ip_address or "—"
        key_str = l.license_key or "—"
        details_str = l.details or "—"
        
        rows_html += f"""
        <tr class="log-row" style="border-bottom: 1px solid var(--border); transition: background 0.15s ease;" onmouseover="this.style.background='rgba(255,255,255,0.02)'" onmouseout="this.style.background='transparent'">
            <td class="mono" style="padding: 14px 20px; font-size: 12px; color: var(--text-muted);">{time_str}</td>
            <td style="padding: 14px 16px;"><span class="status-badge status-{tone}"><span style="width:5px; height:5px; border-radius:50%; background:currentColor;"></span>{l.action}</span></td>
            <td class="mono" style="padding: 14px 16px; font-size: 12px;">{ip_str}</td>
            <td class="mono" style="padding: 14px 16px; font-size: 12.5px; font-weight: 500; color: #c4b5fd;">{key_str}</td>
            <td style="padding: 14px 20px; font-size: 12px; color: var(--text-muted);">{details_str}</td>
        </tr>
        """
        
    if not rows_html:
        rows_html = '<tr id="empty-log-row"><td colspan="5" style="padding: 48px; text-align: center; color: var(--text-muted); font-size: 13px;">No security logs recorded yet.</td></tr>'
        
    content = f"""
    <div style="display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 20px; margin-bottom: 24px;">
        <div class="page-intro" style="margin-bottom: 0;">
            <div class="page-intro-badge">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                Secure administration
            </div>
            <h2 class="page-intro-title">Security event stream</h2>
            <p class="page-intro-text">Trace authorization activity, device anomalies, and administrator actions in real time.</p>
        </div>
        <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
            <button type="button" class="btn btn-danger btn-sm" style="height: 32px; gap: 6px;" onclick="confirmAction({{
                title: 'Clear audit logs?',
                desc: 'Permanently remove all recorded security events, device anomaly logs, and authorization timestamps from the database. This action cannot be undone.',
                action: '/admin/logs/clear',
                confirmText: 'Clear all logs',
                variant: 'danger'
            }})">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                <span>Clear all logs</span>
            </button>
            <button type="button" class="btn btn-secondary btn-sm" id="autoBtn" onclick="toggleAutoRefresh()">
                <svg id="autoIcon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="4" height="16" x="6" y="4"/><rect width="4" height="16" x="14" y="4"/></svg>
                <span id="autoText">Auto-refresh on</span>
            </button>
            <button type="button" class="btn btn-secondary btn-sm" style="padding: 0 10px;" onclick="fetchLiveLogs(true)" title="Refresh now">
                <svg id="refreshIcon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 21h5v-5"/></svg>
            </button>
        </div>
    </div>
    
    {alert_html}
    
    <!-- Filter Search Box -->
    <div class="panel" style="padding: 12px; margin-bottom: 16px;">
        <div style="position: relative; max-width: 440px; display: flex; align-items: center;">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" style="position: absolute; left: 14px; top: 50%; transform: translateY(-50%); pointer-events: none; z-index: 2;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input type="text" id="logFilter" class="input" style="padding-left: 42px !important; height: 38px; font-size: 13px; background: rgba(255, 255, 255, 0.03);" placeholder="Filter action, IP, key, or details" oninput="filterLogs()">
        </div>
    </div>
    
    <!-- Table Panel -->
    <div class="panel" style="overflow-x: auto;">
        <table style="width: 100%; min-width: 800px; border-collapse: collapse; text-align: left;">
            <thead style="background: rgba(255, 255, 255, 0.02); border-bottom: 1px solid var(--border); font-size: 10px; text-transform: uppercase; letter-spacing: 0.12em; color: var(--text-muted);">
                <tr>
                    <th style="padding: 14px 20px; font-weight: 600;">Timestamp</th>
                    <th style="padding: 14px 16px; font-weight: 600;">Action</th>
                    <th style="padding: 14px 16px; font-weight: 600;">IP address</th>
                    <th style="padding: 14px 16px; font-weight: 600;">Key</th>
                    <th style="padding: 14px 20px; font-weight: 600;">Details</th>
                </tr>
            </thead>
            <tbody id="logs-tbody">
                {rows_html}
            </tbody>
        </table>
    </div>
    <p style="margin-top: 12px; text-align: right; font-size: 11px; color: var(--text-muted);">
        Showing <span id="logCount">{len(logs)}</span> security events &middot; live telemetry feed
    </p>

    <script>
    let isAuto = true;
    let timer = null;
    
    function toggleAutoRefresh() {{
        isAuto = !isAuto;
        document.getElementById('autoText').textContent = isAuto ? 'Auto-refresh on' : 'Auto-refresh off';
        if (isAuto) {{
            startPolling();
        }} else {{
            clearInterval(timer);
        }}
    }}
    
    function filterLogs() {{
        const q = document.getElementById('logFilter').value.toLowerCase();
        const rows = document.querySelectorAll('.log-row');
        let count = 0;
        rows.forEach(r => {{
            const text = r.textContent.toLowerCase();
            if (text.includes(q)) {{
                r.style.display = '';
                count++;
            }} else {{
                r.style.display = 'none';
            }}
        }});
        document.getElementById('logCount').textContent = count;
    }}
    
    async function fetchLiveLogs(spin = false) {{
        if (spin) {{
            const icon = document.getElementById('refreshIcon');
            icon.style.transition = 'transform 0.5s ease';
            icon.style.transform = 'rotate(360deg)';
            setTimeout(() => {{ icon.style.transform = 'rotate(0deg)'; }}, 500);
        }}
        try {{
            const res = await fetch('/api/v1/admin/live-logs');
            if (!res.ok) return;
            const data = await res.json();
            if (!Array.isArray(data)) return;
            
            const tbody = document.getElementById('logs-tbody');
            let html = '';
            data.forEach(l => {{
                let tone = 'warning';
                if (l.action.includes('SUCCESS') || l.action.includes('ACTIVATED')) {{
                    tone = 'success';
                }} else if (l.action.includes('BANNED') || l.action.includes('MISMATCH') || l.action.includes('SPAM') || l.action.includes('RATE_LIMIT')) {{
                    tone = 'danger';
                }}
                html += `
                <tr class="log-row" style="border-bottom: 1px solid var(--border); transition: background 0.15s ease;" onmouseover="this.style.background='rgba(255,255,255,0.02)'" onmouseout="this.style.background='transparent'">
                    <td class="mono" style="padding: 14px 20px; font-size: 12px; color: var(--text-muted);">${{l.formatted_time}}</td>
                    <td style="padding: 14px 16px;"><span class="status-badge status-${{tone}}"><span style="width:5px; height:5px; border-radius:50%; background:currentColor;"></span>${{l.action}}</span></td>
                    <td class="mono" style="padding: 14px 16px; font-size: 12px;">${{l.ip_address || '—'}}</td>
                    <td class="mono" style="padding: 14px 16px; font-size: 12.5px; font-weight: 500; color: #c4b5fd;">${{l.license_key || '—'}}</td>
                    <td style="padding: 14px 20px; font-size: 12px; color: var(--text-muted);">${{l.details || '—'}}</td>
                </tr>
                `;
            }});
            tbody.innerHTML = html;
            filterLogs();
        }} catch(e) {{
            console.warn('Log live poll failed:', e);
        }}
    }}
    
    function startPolling() {{
        clearInterval(timer);
        timer = setInterval(() => fetchLiveLogs(false), 3000);
    }}
    startPolling();
    </script>
    """
    return HTMLResponse(content=render_layout("Audit logs", "Security", content, active_tab="logs"))

@app.post("/admin/logs/clear")
async def admin_clear_logs(request: Request, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
        
    try:
        await db.execute(delete(AuditLog))
        await db.commit()
        return RedirectResponse(url="/admin/logs?msg=All+security+audit+logs+have+been+cleared.", status_code=303)
    except Exception as e:
        await db.rollback()
        logger.error(f"Error clearing logs: {e}")
        return RedirectResponse(url="/admin/logs?error=Failed+to+clear+logs.", status_code=303)

# -------------------------------------------------------------
# 8. REAL-TIME JSON APIS FOR WEB TELEMETRY
# -------------------------------------------------------------
@app.get("/api/v1/admin/live-stats")
async def get_live_stats(request: Request, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        raise HTTPException(status_code=403, detail="Unauthorized.")
        
    res_keys = await db.execute(select(License))
    keys = res_keys.scalars().all()
    
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    
    return {
        "total_keys": len(keys),
        "active_keys": sum(1 for k in keys if k.bound_device_hash is not None and not is_license_expired(k) and k.status != "banned"),
        "unused_keys": sum(1 for k in keys if k.bound_device_hash is None and not is_license_expired(k) and k.status != "banned"),
        "expired_keys": sum(1 for k in keys if is_license_expired(k) and k.status != "banned"),
        "banned_keys": sum(1 for k in keys if k.status == "banned"),
        "bound_devices": sum(1 for k in keys if k.bound_device_hash is not None and not is_license_expired(k) and k.status != "banned"),
        "app_status": cfg.app_status if cfg else "ACTIVE",
        "app_version": cfg.app_version if cfg else "1.1.3"
    }

@app.get("/api/v1/admin/live-logs")
async def get_live_logs(request: Request, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        raise HTTPException(status_code=403, detail="Unauthorized.")
        
    result = await db.execute(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100))
    logs = result.scalars().all()
    
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat(),
            "formatted_time": format_nepal_time(l.timestamp, "%Y-%m-%d %H:%M:%S"),
            "action": l.action,
            "ip_address": l.ip_address,
            "license_key": l.license_key or "—",
            "details": l.details
        }
        for l in logs
    ]

# -------------------------------------------------------------
# 9. REST API (iOS CLIENTS & EXTERNAL SCRIPTS)
# -------------------------------------------------------------
class LoginRequest(BaseModel):
    license_key: str
    device_hash: str
    device_name: str = "iPhone"
    device_model: str = "iPhone"
    os_version: str = "iOS"
    app_version: str = "1.1.2"
    timestamp: int
    signature: str

class ValidateRequest(BaseModel):
    token: str
    device_hash: str
    app_version: str = "1.1.2"
    timestamp: int
    signature: str

@app.get("/")
async def root():
    return RedirectResponse(url="/admin/dashboard")

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/api/v1/auth/version-check")
@app.post("/api/v1/auth/version-check")
@app.get("/api/v2/auth/version-check")
@app.post("/api/v2/auth/version-check")
async def check_app_version(db: AsyncSession = Depends(get_db)):
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    required_ver = cfg.app_version.strip() if (cfg and cfg.app_version) else "1.1.2"
    force_update = cfg.force_update if cfg else False
    notes = cfg.release_notes.strip() if (cfg and cfg.release_notes and cfg.release_notes.strip()) else "Official Release v1.1.2: Added Visuals (Hologram Location Exposed), Aim Drag, 144 FPS Unlock, Aim Body, and Magic Bullet with ultra-smooth engine performance and dynamic cloud delivery."
    download_url = cfg.download_url if (cfg and cfg.download_url and cfg.download_url.strip()) else "https://github.com/nicchen0xf/Swift-ios/releases"
    app_status = cfg.app_status if cfg else "ACTIVE"
    maint_msg = cfg.maintenance_message.strip() if (cfg and cfg.maintenance_message and cfg.maintenance_message.strip()) else "Panel is Under Maintainance."
    return {
        "app_status": app_status,
        "maintenance_message": maint_msg,
        "latest_version": required_ver,
        "force_update": force_update,
        "release_notes": notes,
        "download_url": download_url
    }

class NativeActivationRequest(BaseModel):
    key: str
    publicKey: Optional[str] = None

class NativeChallengeRequest(BaseModel):
    activationId: str

class NativeVerificationRequest(BaseModel):
    activationId: str
    challengeId: str
    signature: str

native_challenges: Dict[str, Dict[str, Any]] = {}

@app.post("/v1/activations")
@app.post("/api/v1/activations")
async def handle_native_activation(
    req: NativeActivationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    client_ip = get_real_client_ip(request)
    key_clean = req.key.strip().upper()
    
    # Check rate limit
    check_endpoint_rate_limit(f"act:{key_clean}:{client_ip}", 30, 60)
    
    # 1. Maintenance Check
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    if cfg and cfg.app_status == "PAUSED":
        maint_detail = cfg.maintenance_message.strip() if (cfg.maintenance_message and cfg.maintenance_message.strip()) else "Panel is Under Maintainance."
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "service_paused", "detail": maint_detail, "code": "MAINTENANCE"}
        )

    # 2. Lookup License Key in Database
    result = await db.execute(select(License).where(func.upper(License.key) == key_clean))
    lic = result.scalars().first()
    if not lic:
        log = AuditLog(
            action="NATIVE_ACT_FAILED_INVALID_KEY",
            ip_address=client_ip,
            license_key=req.key,
            details="Activation attempted with non-existent license key."
        )
        db.add(log)
        await db.commit()
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "invalid_key", "detail": "Invalid license key provided.", "code": "INVALID_KEY"}
        )

    if lic.status == "banned":
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "banned_key", "detail": "License key is blacklisted.", "code": "BANNED"}
        )
    if lic.status == "revoked":
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "revoked_key", "detail": "License key revoked.", "code": "REVOKED"}
        )
    if is_license_expired(lic):
        lic.status = "expired"
        await db.commit()
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "expired_key", "detail": "License key has expired.", "code": "EXPIRED"}
        )

    activation_id = str(uuid.uuid4())
    act_rec = LicenseActivation(
        activation_id=activation_id,
        license_key=lic.key,
        public_key=req.publicKey.strip() if req.publicKey else None,
        created_at=utc_now(),
        last_verified_at=utc_now()
    )
    db.add(act_rec)
    
    log = AuditLog(
        action="NATIVE_ACTIVATION_ISSUED",
        ip_address=client_ip,
        license_key=lic.key,
        details=f"Activation ID {activation_id} issued."
    )
    db.add(log)
    await db.commit()
    
    return {"activationId": activation_id}

@app.post("/v1/challenges")
@app.post("/api/v1/challenges")
async def handle_native_challenge(
    req: NativeChallengeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    client_ip = get_real_client_ip(request)
    act_id = req.activationId.strip()
    
    res = await db.execute(select(LicenseActivation).where(LicenseActivation.activation_id == act_id))
    act_rec = res.scalars().first()
    if not act_rec:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "invalid_activation", "detail": "Activation session not found.", "code": "INVALID_ACTIVATION"}
        )
        
    res_lic = await db.execute(select(License).where(License.key == act_rec.license_key))
    lic = res_lic.scalars().first()
    if not lic or lic.status != "active" or is_license_expired(lic):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "license_inactive", "detail": "Associated license is not active.", "code": "INACTIVE"}
        )
        
    challenge_id = str(uuid.uuid4())
    nonce = secrets.token_hex(32)
    
    native_challenges[challenge_id] = {
        "activation_id": act_id,
        "nonce": nonce,
        "license_key": lic.key,
        "created_at": time.time()
    }
    
    return {
        "challengeId": challenge_id,
        "nonce": nonce
    }

@app.post("/v1/verifications")
@app.post("/api/v1/verifications")
async def handle_native_verification(
    req: NativeVerificationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    client_ip = get_real_client_ip(request)
    act_id = req.activationId.strip()
    chal_id = req.challengeId.strip()
    
    challenge_info = native_challenges.pop(chal_id, None)
    if not challenge_info or challenge_info.get("activation_id") != act_id:
        res_act = await db.execute(select(LicenseActivation).where(LicenseActivation.activation_id == act_id))
        act_rec = res_act.scalars().first()
        if not act_rec:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "invalid_challenge", "detail": "Challenge expired or invalid.", "code": "INVALID_CHALLENGE"}
            )
        lic_key = act_rec.license_key
    else:
        lic_key = challenge_info["license_key"]
        
    res_lic = await db.execute(select(License).where(License.key == lic_key))
    lic = res_lic.scalars().first()
    if not lic:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "invalid_key", "detail": "License key not found.", "code": "INVALID_KEY"}
        )
        
    if lic.status == "banned" or lic.status == "revoked" or is_license_expired(lic):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "license_disabled", "detail": "License is inactive or expired.", "code": "DISABLED"}
        )
        
    now = utc_now()
    if not lic.activated_at:
        lic.activated_at = now
        if lic.duration_days and lic.duration_days > 0 and not lic.expires_at:
            lic.expires_at = now + datetime.timedelta(days=lic.duration_days)
            
    if not lic.bound_device_hash:
        lic.bound_device_hash = f"ios_{act_id[:16]}"
        
    log = AuditLog(
        action="NATIVE_VERIFICATION_SUCCESS",
        ip_address=client_ip,
        license_key=lic.key,
        details=f"Activation {act_id} successfully verified."
    )
    db.add(log)
    await db.commit()
    
    return {
        "status": "active"
    }

@app.post("/api/v1/auth/login")
async def login_v1_handler(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    try:
        body = await request.json()
    except Exception:
        body = {}
    key = body.get("key") or body.get("license_key") or ""
    client_ip = get_real_client_ip(request)
    if not key:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "missing_key", "detail": "License key is required."}
        )
    key_clean = str(key).strip().upper()
    device_hash_clean = (body.get("device_hash") or f"ios_{client_ip.replace('.', '_')}").strip()
    device_name = str(body.get("device_name") or "iOS Device").strip()
    device_model = str(body.get("device_model") or "iPhone").strip()
    os_version = str(body.get("os_version") or "iOS").strip()

    # 1. Maintenance Check
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    if cfg and cfg.app_status == "PAUSED":
        maint_detail = cfg.maintenance_message.strip() if (cfg.maintenance_message and cfg.maintenance_message.strip()) else "Panel is Under Maintainance."
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "service_paused", "status": "PAUSED", "detail": maint_detail}
        )

    # 2. Rate limit check (5 attempts / 60s)
    try:
        check_and_enforce_rate_limit(client_ip=client_ip, device_hash=device_hash_clean)
    except HTTPException as e:
        return JSONResponse(
            status_code=e.status_code,
            content={"error": "rate_limit", "detail": e.detail}
        )

    # 3. Register or Fetch Device
    try:
        device = await get_or_register_device(
            db=db,
            device_hash=device_hash_clean,
            device_name=device_name,
            device_model=device_model,
            os_version=os_version,
            client_ip=client_ip,
            public_key=None
        )
    except HTTPException as e:
        return JSONResponse(
            status_code=e.status_code,
            content={"error": "device_error", "detail": e.detail}
        )

    # 4. Activate or Verify License Key
    try:
        lic = await activate_or_verify_license(
            db=db,
            license_key=key_clean,
            device=device,
            client_ip=client_ip
        )
    except HTTPException as e:
        return JSONResponse(
            status_code=e.status_code,
            content={"error": "license_error", "detail": e.detail}
        )

    # 5. Mint and Persist Session Token
    session_id = str(uuid.uuid4())
    jwt_token = create_access_token({
        "sub": session_id,
        "lic": lic.key,
        "hwid": device.device_hash,
        "protocol": "v1_compat"
    })
    
    session_record = SessionToken(
        session_id=session_id,
        device_hash=device.device_hash,
        license_key=lic.key,
        token=jwt_token,
        created_at=utc_now(),
        last_heartbeat=utc_now()
    )
    db.add(session_record)
    
    log = AuditLog(
        action="LOGIN_V1_SUCCESS",
        ip_address=client_ip,
        device_hash=device.device_hash,
        license_key=mask_license_key(lic.key),
        details=f"V1 Session granted to {device.device_name} ({device.device_model})."
    )
    db.add(log)
    await db.commit()

    return {
        "success": True,
        "status": "active",
        "token": jwt_token,
        "expires_at": lic.expires_at.isoformat() if lic.expires_at else "LIFETIME",
        "server_time": int(utc_now().timestamp())
    }

@app.post("/api/v1/auth/validate")
@app.post("/api/v2/auth/validate")
async def validate_heartbeat(req: ValidateRequest, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = get_real_client_ip(request)
    
    # Rate Limiting on Validation: max 60 per minute
    check_endpoint_rate_limit(f"val:{req.device_hash.strip()}:{client_ip}", settings.RATE_LIMIT_VALIDATE_MAX, 60)
    
    # 0. Controlled Protocol v1 Retirement Check
    if request.url.path.startswith("/api/v1/") and not getattr(settings, "ENABLE_V1_PROTOCOL", True):
        return JSONResponse(
            status_code=status.HTTP_410_GONE,
            content={
                "error": "protocol_retired",
                "detail": "Protocol v1 validation has been retired. Please update to iOS client v2."
            },
            headers={"X-API-Deprecation": "protocol=v1; status=retired; upgrade=/api/v2/auth/validate"}
        )

    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    if cfg and cfg.app_status == "PAUSED":
        maint_detail = cfg.maintenance_message.strip() if (cfg.maintenance_message and cfg.maintenance_message.strip()) else "Panel is Under Maintainance."
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "service_paused",
                "status": "PAUSED",
                "message": maint_detail,
                "detail": maint_detail
            }
        )
        
    if cfg:
        required_ver = cfg.app_version.strip() if cfg.app_version else "1.1.2"
        client_ver = req.app_version.strip() if req.app_version else "1.1.2"
        def parse_v(v: str):
            try:
                parts = v.lower().replace('v', '').split('.')
                return tuple(int(x) for x in parts if x.isdigit())
            except Exception:
                return (0, 0, 0)
        is_mismatch = (client_ver != required_ver)
        is_older = (parse_v(client_ver) < parse_v(required_ver))
        if (cfg.force_update and is_mismatch) or is_older:
            notes = cfg.release_notes.strip() if (cfg.release_notes and cfg.release_notes.strip()) else "A new update is available."
            download_url = cfg.download_url if (cfg.download_url and cfg.download_url.strip()) else "https://github.com/nicchennnnn/External/releases"
            return JSONResponse(
                status_code=status.HTTP_426_UPGRADE_REQUIRED,
                content={
                    "error": "update_required",
                    "latest_version": required_ver,
                    "release_notes": notes,
                    "download_url": download_url,
                    "detail": notes
                }
            )

    payload = decode_access_token(req.token)
    if not payload:
        raise HTTPException(status_code=401, detail="Session expired or invalid.")
        
    hwid = payload.get("hwid")
    session_id = payload.get("sub")
    
    if hwid != req.device_hash.strip():
        raise HTTPException(status_code=403, detail="HWID mismatch.")
        
    result = await db.execute(select(SessionToken).where(SessionToken.session_id == session_id))
    session_rec = result.scalars().first()
    if not session_rec or session_rec.is_revoked:
        raise HTTPException(status_code=401, detail="Session revoked.")

    # Validate underlying license status & expiration during heartbeat
    res_lic = await db.execute(select(License).where(License.key == session_rec.license_key))
    lic = res_lic.scalars().first()
    if not lic:
        session_rec.is_revoked = True
        await db.commit()
        raise HTTPException(status_code=401, detail="Session revoked: License not found.")
        
    if lic.status == "banned":
        session_rec.is_revoked = True
        await db.commit()
        raise HTTPException(status_code=403, detail="License key blacklisted.")
        
    if lic.status == "revoked":
        session_rec.is_revoked = True
        await db.commit()
        raise HTTPException(status_code=403, detail="License key revoked.")

    if is_license_expired(lic):
        lic.status = "expired"
        session_rec.is_revoked = True
        await db.commit()
        raise HTTPException(status_code=403, detail="License key has expired.")
        
    now_dt = utc_now()
    if session_rec.last_heartbeat is None or (now_dt - session_rec.last_heartbeat).total_seconds() >= 60:
        session_rec.last_heartbeat = now_dt
        await db.commit()
    
    server_time = int(utc_now().timestamp())
    return {
        "valid": True,
        "status": "active",
        "server_time": server_time,
        "signature": sign_payload(f"VALID:{hwid}:{server_time}")
    }

# -------------------------------------------------------------
# 9.1 SECURE DYNAMIC CLOUD PATCH DELIVERY ENDPOINTS
# -------------------------------------------------------------
class PatchFetchRequest(BaseModel):
    feature_name: str = Field(..., description="Feature identifier: 'avatar', '144', 'magic', 'aimbody'")
    token: str = Field(..., description="JWT session token")
    device_hash: str = Field(..., description="Device HWID hash")
    timestamp: int = Field(..., description="UNIX epoch seconds for anti-replay")
    signature: str = Field(..., description="HMAC-SHA256 signature of 'feature_name:device_hash:timestamp'")
    app_version: Optional[str] = Field(default="1.1.3", description="Client iOS App Version")

FEATURE_FILE_MAP = {
    "avatar": "Avatar Drag.3105",
    "aim_drag": "Avatar Drag.3105",
    "144": "144 FPS.3105",
    "fps_144": "144 FPS.3105",
    "magic": "Magic.3105",
    "magic_bullet": "Magic.3105",
    "aimbody": "Aimbody.3105",
    "body_drag": "Aimbody.3105",
    "hologram": "Hologram.3105",
    "visuals": "Hologram.3105",
    # Mod Skins Cloud Delivery
    "mod_ignis": "Mod_Ignis.3105",
    "ignis": "Mod_Ignis.3105",
    "mod_bunny": "Mod_Bunny.3105",
    "bunny": "Mod_Bunny.3105",
    "mod_spider": "Mod_Spider.3105",
    "spider": "Mod_Spider.3105",
    "mod_gojo": "Mod_Gojo.3105",
    "gojo": "Mod_Gojo.3105",
}

@app.post("/api/v1/patches/fetch")
@app.post("/api/v2/patches/fetch")
async def fetch_patch(req: PatchFetchRequest, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = get_real_client_ip(request)
    feature_key = req.feature_name.strip().lower()
    device_hash_clean = req.device_hash.strip()
    
    # Rate Limiting on Binary Patch Downloads: max 15 per minute
    check_endpoint_rate_limit(f"patch:{device_hash_clean}:{client_ip}", settings.RATE_LIMIT_PATCH_FETCH_MAX, 60)
    
    # 0. Controlled Protocol v1 Retirement Check
    if request.url.path.startswith("/api/v1/") and not getattr(settings, "ENABLE_V1_PROTOCOL", True):
        return JSONResponse(
            status_code=status.HTTP_410_GONE,
            content={
                "error": "protocol_retired",
                "detail": "Protocol v1 patch delivery has been retired. Please update to iOS client v2."
            },
            headers={"X-API-Deprecation": "protocol=v1; status=retired; upgrade=/api/v2/patches/fetch"}
        )

    # 1. Maintenance / Killswitch Check
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    if cfg and cfg.app_status == "PAUSED":
        maint_detail = cfg.maintenance_message.strip() if (cfg.maintenance_message and cfg.maintenance_message.strip()) else "Panel is Under Maintainance."
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "service_paused",
                "status": "PAUSED",
                "message": maint_detail,
                "detail": maint_detail
            }
        )

    # 2. Dynamic App Version Check & Force-Update Policy
    if cfg:
        required_ver = cfg.app_version.strip() if cfg.app_version else "1.1.3"
        client_ver = (req.app_version or "1.1.3").strip()
        
        def parse_v(v: str):
            try:
                parts = v.lower().replace('v', '').split('.')
                return tuple(int(x) for x in parts if x.isdigit())
            except Exception:
                return (0, 0, 0)
                
        is_mismatch = (client_ver != required_ver)
        is_older = (parse_v(client_ver) < parse_v(required_ver))
        
        if (cfg.force_update and is_mismatch) or is_older:
            notes = cfg.release_notes.strip() if (cfg.release_notes and cfg.release_notes.strip()) else "A new update is available."
            download_url = cfg.download_url if (cfg.download_url and cfg.download_url.strip()) else "https://github.com/nicchen0xf/Swift-ios/releases"
            return JSONResponse(
                status_code=status.HTTP_426_UPGRADE_REQUIRED,
                content={
                    "error": "update_required",
                    "latest_version": required_ver,
                    "release_notes": notes,
                    "download_url": download_url,
                    "detail": notes
                }
            )
        
    # 3. Anti-Replay & HMAC Signature Check ('feature_name:device_hash:timestamp')
    current_time = int(time.time())
    if abs(current_time - req.timestamp) > 90:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request timestamp expired. Please check device clock."
        )
        
    sig_payload = f"{feature_key}:{device_hash_clean}:{req.timestamp}"
    if not verify_hmac_signature(sig_payload, req.signature.strip()):
        if not request.url.path.startswith("/api/v2/"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid patch delivery signature (HMAC Tamper Triggered)."
            )
        
    # 4. Session JWT Token Validation & HWID Binding
    payload = decode_access_token(req.token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid.")
        
    token_hwid = payload.get("hwid")
    session_id = payload.get("sub")
    license_key = payload.get("lic")
    
    if token_hwid != device_hash_clean:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Hardware device mismatch.")
        
    # 5. Check Database Session, Device & License Key Validation Status
    result = await db.execute(select(SessionToken).where(SessionToken.session_id == session_id))
    session_rec = result.scalars().first()
    if not session_rec or session_rec.is_revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked.")
        
    res_dev = await db.execute(select(Device).where(Device.device_hash == device_hash_clean))
    device = res_dev.scalars().first()
    if not device or device.is_banned:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device has been suspended or banned.")
        
    res_lic = await db.execute(select(License).where(License.key == license_key))
    lic = res_lic.scalars().first()
    if not lic:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="License key not found.")
    if is_license_expired(lic):
        lic.status = "expired"
        await db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="License key has expired.")
    if lic.status != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"License is {lic.status}.")
    if lic.bound_device_hash and lic.bound_device_hash != device_hash_clean:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="License key is locked to another hardware device.")
        
    # 5. Resolve Target Patch File with Strict Path Traversal Prevention
    patch_filename = FEATURE_FILE_MAP.get(feature_key)
    if not patch_filename:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Feature '{req.feature_name}' not found.")
        
    base_storage = os.path.realpath(os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage", "patches")))
    patch_path = os.path.realpath(os.path.abspath(os.path.join(base_storage, patch_filename)))
    
    # Path Traversal Guard: canonical target must reside inside base_storage (Symlink safe)
    if os.path.commonpath([base_storage, patch_path]) != base_storage:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid patch path.")
        
    if not os.path.exists(patch_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Patch file for '{req.feature_name}' unavailable on server.")
        
    with open(patch_path, "rb") as f:
        patch_bytes = f.read()
        
    # Update Session Heartbeat & Audit Log
    session_rec.last_heartbeat = utc_now()
    log = AuditLog(
        action="PATCH_FETCH_SUCCESS",
        ip_address=client_ip,
        device_hash=device_hash_clean,
        license_key=mask_license_key(license_key),
        details=f"Delivered cloud patch '{patch_filename}' ({len(patch_bytes)} bytes) to {device.device_name}."
    )
    db.add(log)
    await db.commit()
    
    # 6. Stream Binary Data with Integrity Headers
    file_hash = hashlib.sha256(patch_bytes).hexdigest()
    resp_sig = sign_payload(f"{feature_key}:{file_hash}:{current_time}")
    
    return Response(
        content=patch_bytes,
        media_type="application/octet-stream",
        headers={
            "X-Patch-Filename": patch_filename,
            "X-Patch-SHA256": file_hash,
            "X-Patch-Timestamp": str(current_time),
            "X-Patch-Signature": resp_sig,
        }
    )

@app.get("/api/v1/patches/catalog")
async def list_available_patches():
    return {
        "status": "available",
        "features": [
            {"id": "avatar", "name": "Aim Drag", "file": "Avatar Drag.3105"},
            {"id": "144", "name": "144 FPS Unlock", "file": "144 FPS.3105"},
            {"id": "magic", "name": "Magic Bullet", "file": "Magic.3105"},
            {"id": "aimbody", "name": "Aim Body", "file": "Aimbody.3105"},
            {"id": "hologram", "name": "Visuals", "file": "Hologram.3105"},
            {"id": "mod_ignis", "name": "Mod Ignis", "file": "Mod_Ignis.3105"},
            {"id": "mod_bunny", "name": "Mod Bunny", "file": "Mod_Bunny.3105"},
            {"id": "mod_spider", "name": "Mod Spider", "file": "Mod_Spider.3105"},
            {"id": "mod_gojo", "name": "Mod Gojo", "file": "Mod_Gojo.3105"}
        ]
    }

# -------------------------------------------------------------
# 9.2 PROTOCOL V2: ASYMMETRIC DEVICE-KEY CHALLENGE/RESPONSE (MIGRATION PATH)
# Eliminates global embedded HMAC secret on the iOS client
# -------------------------------------------------------------
v2_challenges: Dict[str, Dict[str, Any]] = {} # nonce -> {"device_hash": ..., "created_at": ...}
v2_challenge_lock = asyncio.Lock() # Atomic concurrency lock for challenge consumption

class V2ChallengeRequest(BaseModel):
    device_hash: str = Field(..., min_length=16, max_length=128)
    client_version: str = Field(default="2.0.0", max_length=32)

@app.post("/api/v2/auth/challenge")
async def request_v2_challenge(req: V2ChallengeRequest, request: Request):
    """
    Issues a single-use cryptographically random nonce bound to a specific device HWID.
    Expires strictly after 120 seconds.
    """
    client_ip = get_real_client_ip(request)
    check_endpoint_rate_limit(f"v2_chall:{req.device_hash.strip()}:{client_ip}", 20, 60)
    
    bounded_cleanup()
    nonce = secrets.token_hex(32)
    async with v2_challenge_lock:
        v2_challenges[nonce] = {
            "device_hash": req.device_hash.strip(),
            "created_at": time.time()
        }
    
    return {
        "success": True,
        "nonce": nonce,
        "device_hash": req.device_hash.strip(),
        "server_time": int(time.time()),
        "expires_in": 120
    }

class V2LoginRequest(BaseModel):
    license_key: str = Field(..., min_length=8, max_length=64)
    device_hash: str = Field(..., min_length=16, max_length=128)
    nonce: str = Field(..., min_length=32, max_length=128)
    device_public_key: str = Field(..., min_length=32, description="Hex/Base64/PEM public key generated in Secure Enclave")
    device_signature: str = Field(..., min_length=32, description="ECDSA P-256 or Ed25519 signature over canonical challenge context")
    device_name: str = Field(default="iPhone", max_length=100)
    device_model: str = Field(default="iPhone", max_length=64)
    os_version: str = Field(default="iOS", max_length=32)
    app_version: str = Field(default="2.0.0", max_length=32)

@app.post("/api/v2/auth/login")
async def login_v2(req: V2LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """
    V2 Authenticated Login: Verifies single-use server nonce and binds device public key.
    Provides asymmetric authentication, maintenance gating, and version enforcement.
    """
    client_ip = get_real_client_ip(request)
    now = time.time()
    device_hash_clean = req.device_hash.strip()
    license_key_clean = req.license_key.strip()
    
    # 1. Killswitch & Maintenance check
    res_cfg = await db.execute(select(SystemConfig))
    cfg = res_cfg.scalars().first()
    if cfg and cfg.app_status == "PAUSED":
        maint_detail = cfg.maintenance_message.strip() if (cfg.maintenance_message and cfg.maintenance_message.strip()) else "Panel is Under Maintainance."
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "service_paused",
                "status": "PAUSED",
                "message": maint_detail,
                "detail": maint_detail
            }
        )
        
    # 2. App Version & Update Enforcement Check
    if cfg:
        required_ver = cfg.app_version.strip() if cfg.app_version else "1.1.3"
        client_ver = req.app_version.strip() if req.app_version else "1.1.3"
        
        def parse_v(v: str):
            try:
                parts = v.lower().replace('v', '').split('.')
                return tuple(int(x) for x in parts if x.isdigit())
            except Exception:
                return (0, 0, 0)
                
        is_mismatch = (client_ver != required_ver)
        is_older = (parse_v(client_ver) < parse_v(required_ver))
        
        if (cfg.force_update and is_mismatch) or is_older:
            notes = cfg.release_notes.strip() if (cfg.release_notes and cfg.release_notes.strip()) else "A new update is available."
            download_url = cfg.download_url if (cfg.download_url and cfg.download_url.strip()) else "https://github.com/nicchen0xf/Swift-ios/releases"
            return JSONResponse(
                status_code=status.HTTP_426_UPGRADE_REQUIRED,
                content={
                    "error": "update_required",
                    "latest_version": required_ver,
                    "release_notes": notes,
                    "download_url": download_url,
                    "detail": notes
                }
            )

    # 3. Dual-Layer 10-Minute Timeout Jail Rate Limiter (5 attempts / 60s)
    try:
        check_and_enforce_rate_limit(client_ip=client_ip, device_hash=device_hash_clean)
    except HTTPException as e:
        if e.status_code == status.HTTP_429_TOO_MANY_REQUESTS and getattr(e, "headers", None) and e.headers.get("X-New-Lockout") == "1":
            try:
                log = AuditLog(
                    action="SPAM_RATE_LIMIT_TRIGGERED",
                    ip_address=client_ip,
                    device_hash=device_hash_clean,
                    license_key=mask_license_key(license_key_clean),
                    details="V2 Login Rate limit exceeded (5 attempts). 10-minute lockout enforced."
                )
                db.add(log)
                await db.commit()
            except Exception:
                pass
        raise e
    
    # 4. Nonce Validity & Atomic Single-Use Consumption
    async with v2_challenge_lock:
        challenge_data = v2_challenges.pop(req.nonce.strip(), None)
        
    if not challenge_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nonce expired or already consumed. Please request a new challenge."
        )
    if (now - challenge_data["created_at"]) > 120:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nonce expired. Please request a new challenge."
        )
    if challenge_data["device_hash"] != device_hash_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nonce device binding mismatch. Challenge was issued to another hardware device."
        )
        
    # 5. Cryptographic Asymmetric Signature Verification over Canonical Context
    canonical_message = f"V2-AUTH:{req.nonce.strip()}:{license_key_clean.upper()}:{device_hash_clean}:{req.app_version.strip()}".encode('utf-8')
    is_sig_valid = verify_asymmetric_device_signature(
        public_key_str=req.device_public_key.strip(),
        message_bytes=canonical_message,
        signature_str=req.device_signature.strip()
    )
    if not is_sig_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Cryptographic device signature verification failed."
        )
    
    # 6. Device Registration, Public Key Enrollment & Substitution Protection
    device = await get_or_register_device(
        db=db,
        device_hash=device_hash_clean,
        device_name=req.device_name.strip(),
        device_model=req.device_model.strip(),
        os_version=req.os_version.strip(),
        client_ip=client_ip,
        public_key=req.device_public_key.strip()
    )
    
    # 7. Atomic License Activation
    license_obj = await activate_or_verify_license(
        db=db,
        license_key=license_key_clean,
        device=device,
        client_ip=client_ip
    )
    
    # 8. Mint Session JWT
    session_id = str(uuid.uuid4())
    jwt_token = create_access_token({
        "sub": session_id,
        "lic": license_obj.key,
        "hwid": device.device_hash,
        "protocol": "v2_asymmetric"
    })
    
    session_record = SessionToken(
        session_id=session_id,
        device_hash=device.device_hash,
        license_key=license_obj.key,
        token=jwt_token,
        created_at=utc_now(),
        last_heartbeat=utc_now()
    )
    db.add(session_record)
    
    log = AuditLog(
        action="LOGIN_V2_SUCCESS",
        ip_address=client_ip,
        device_hash=device.device_hash,
        license_key=mask_license_key(license_obj.key),
        details=f"V2 Asymmetric Session granted to {device.device_name}."
    )
    db.add(log)
    await db.commit()
    
    return {
        "success": True,
        "status": "authenticated",
        "protocol": "v2",
        "token": jwt_token,
        "expires_at": license_obj.expires_at.isoformat() if license_obj.expires_at else "LIFETIME",
        "server_time": int(utc_now().timestamp())
    }

# -------------------------------------------------------------
# 9.2 RELEASE CHANGELOG & PACKAGE TRACKING CLIENT API ENDPOINTS
# -------------------------------------------------------------
class ReleaseCheckRequest(BaseModel):
    device_hash: str = Field(..., description="Device HWID hash")
    token: str = Field(..., description="Active session JWT token")

class ReleaseAckRequest(BaseModel):
    device_hash: str = Field(..., description="Device HWID hash")
    token: str = Field(..., description="Active session JWT token")
    release_id: str = Field(..., description="Unique release ID")

@app.post("/api/v2/releases/unseen")
async def get_unseen_releases_endpoint(req: ReleaseCheckRequest, request: Request, db: AsyncSession = Depends(get_db)):
    payload = decode_access_token(req.token)
    if not payload or payload.get("hwid") != req.device_hash.strip():
        raise HTTPException(status_code=401, detail="Invalid session or HWID mismatch.")
        
    unseen = await get_unseen_releases_for_device(req.device_hash.strip(), db)
    return {
        "status": "ok",
        "count": len(unseen),
        "unseen_releases": unseen
    }

@app.post("/api/v2/releases/acknowledge")
async def acknowledge_release_endpoint(req: ReleaseAckRequest, request: Request, db: AsyncSession = Depends(get_db)):
    payload = decode_access_token(req.token)
    if not payload or payload.get("hwid") != req.device_hash.strip():
        raise HTTPException(status_code=401, detail="Invalid session or HWID mismatch.")
        
    license_key = payload.get("lic")
    await record_user_acknowledgment(
        device_hash=req.device_hash.strip(),
        release_id=req.release_id.strip(),
        license_key=license_key,
        db=db
    )
    return {"status": "ok", "acknowledged": True, "release_id": req.release_id.strip()}

# -------------------------------------------------------------
# 9.3 ADMIN RELEASES & PACKAGE CHANGELOG MANAGEMENT
# -------------------------------------------------------------
@app.get("/admin/releases", response_class=HTMLResponse)
async def admin_releases_page(request: Request, msg: Optional[str] = None, err: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)

    # 1. Inspect physical packages on disk
    packages_info = []
    if os.path.isdir(STORAGE_PATCHES_DIR):
        for f in sorted(os.listdir(STORAGE_PATCHES_DIR)):
            if f.endswith(".3105"):
                f_path = os.path.join(STORAGE_PATCHES_DIR, f)
                size_mb = round(os.path.getsize(f_path) / (1024 * 1024), 2)
                with open(f_path, "rb") as pf:
                    f_hash = hashlib.sha256(pf.read()).hexdigest()
                
                latest_rel = await get_latest_release_for_filename(f, db)
                packages_info.append({
                    "filename": f,
                    "name": normalize_package_name_from_filename(f),
                    "size_mb": size_mb,
                    "sha256": f_hash,
                    "release_id": latest_rel.release_id if latest_rel else "None",
                    "release_id": latest_rel.release_id if latest_rel else None,
                    "version": latest_rel.version_tag if latest_rel else "—",
                    "published_at": format_nepal_time(latest_rel.published_at, "%Y-%m-%d %H:%M") if (latest_rel and latest_rel.published_at) else "—"
                })

    # 2. Query Release History
    res_history = await db.execute(select(PackageRelease).order_by(desc(PackageRelease.published_at)).limit(40))
    releases = res_history.scalars().all()

    # Query Acknowledgment counts per release
    res_acks = await db.execute(
        select(UserReleaseAcknowledgment.release_id, func.count(UserReleaseAcknowledgment.id))
        .group_by(UserReleaseAcknowledgment.release_id)
    )
    ack_map = {r[0]: r[1] for r in res_acks.all()}

    alert_html = ""
    if msg:
        alert_html = f'<div class="status-badge status-success" style="margin-bottom: 20px; padding: 10px 16px; font-size: 13px;"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>{msg}</div>'
    elif err:
        alert_html = f'<div class="status-badge status-danger" style="margin-bottom: 20px; padding: 10px 16px; font-size: 13px;"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>{err}</div>'

    pkg_rows_html = ""
    for p in packages_info:
        rel_badge = f'<span class="status-badge status-success">{p["release_id"]}</span>' if p["release_id"] else '<span class="status-badge status-neutral" style="opacity: 0.7;">Unpublished</span>'
        pkg_rows_html += f"""
        <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 12px 16px; font-weight: 600;">{p['name']}</td>
            <td class="mono" style="padding: 12px 16px; font-size: 12px; color: var(--text-muted);">{p['filename']}</td>
            <td class="mono" style="padding: 12px 16px; font-size: 11px; color: var(--accent);">{p['sha256'][:16]}…</td>
            <td style="padding: 12px 16px; font-size: 12px;">{p['size_mb']} MB</td>
            <td class="mono" style="padding: 12px 16px; font-size: 12px;">{rel_badge}</td>
            <td style="padding: 12px 16px; font-size: 12px; color: var(--text-muted);">{p['published_at']}</td>
        </tr>
        """

    rel_rows_html = ""
    for r in releases:
        time_str = format_nepal_time(r.published_at, "%Y-%m-%d %H:%M")
        seen_count = ack_map.get(r.release_id, 0)
        rel_rows_html += f"""
        <tr style="border-bottom: 1px solid var(--border);">
            <td class="mono" style="padding: 12px 16px; font-size: 12px; color: var(--text-muted);">{time_str}</td>
            <td style="padding: 12px 16px; font-weight: 600;">{r.package_name} <span class="mono" style="font-size:11px; color:var(--text-muted);">({r.version_tag})</span></td>
            <td class="mono" style="padding: 12px 16px; font-size: 12px;"><span class="status-badge status-neutral">{r.release_id}</span></td>
            <td class="mono" style="padding: 12px 16px; font-size: 11px; color: var(--text-muted);">{r.file_sha256[:16]}…</td>
            <td style="padding: 12px 16px; font-size: 12px; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{r.release_notes}</td>
            <td style="padding: 12px 16px; font-size: 12px;"><span style="color:var(--success); font-weight:600;">{seen_count}</span> devices acknowledged</td>
        </tr>
        """
    if not rel_rows_html:
        rel_rows_html = """
        <tr>
            <td colspan="6" style="padding: 48px 24px; text-align: center; color: var(--text-muted); font-size: 13px;">
                <div style="font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 6px;">No Package Releases Published Yet</div>
                <div>When you update a package (e.g. <code>Avatar Drag.3105</code>), upload it above to publish a release ID and trigger the iOS in-app update notice.</div>
            </td>
        </tr>
        """

    content = f"""
    <div style="display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 20px; margin-bottom: 24px;">
        <div class="page-intro" style="margin-bottom: 0;">
            <div class="page-intro-badge">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                Package Release Management
            </div>
            <h2 class="page-intro-title">Releases & update changelogs</h2>
            <p class="page-intro-text">Upload or replace package binaries, generate unique cryptographic release tracking IDs, and publish in-app changelogs for iOS clients.</p>
        </div>
    </div>

    {alert_html}

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 24px; margin-bottom: 28px;">
        <!-- Upload & Replace Package Card -->
        <div class="panel" style="min-width: 0;">
            <div class="panel-header" style="border-bottom: 1px solid var(--border); padding: 18px 24px;">
                <div class="panel-title" style="display: flex; align-items: center; gap: 8px; font-size: 15px; font-weight: 600;">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    Upload / Replace Package (.3105)
                </div>
            </div>
            <div class="panel-body" style="padding: 24px;">
                <form action="/admin/releases/upload" method="POST" enctype="multipart/form-data">
                    <div style="margin-bottom: 14px;">
                        <label style="display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px;">Select .3105 Package File</label>
                        <input type="file" name="package_file" required accept=".3105" class="form-input" style="width: 100%; box-sizing: border-box; padding: 8px;">
                    </div>
                    <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 12px; margin-bottom: 14px;">
                        <div>
                            <label style="display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px;">Package Display Name (Optional)</label>
                            <input type="text" name="package_name" placeholder="Leave blank to auto-detect from filename" class="form-input" style="width: 100%; box-sizing: border-box;">
                        </div>
                        <div>
                            <label style="display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px;">Version Tag</label>
                            <input type="text" name="version_tag" value="v1.1" placeholder="v1.1" class="form-input" style="width: 100%; box-sizing: border-box;">
                        </div>
                    </div>
                    <div style="margin-bottom: 18px;">
                        <label style="display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px;">Release Notes / What's New</label>
                        <textarea name="release_notes" required rows="4" placeholder="• Improved stability&#10;• Updated game offsets for latest patch&#10;• Performance improvements" class="form-input" style="width: 100%; box-sizing: border-box; resize: vertical;"></textarea>
                    </div>
                    <div style="display: flex; justify-content: flex-end;">
                        <button type="submit" class="btn btn-primary" style="gap: 8px;">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
                            <span>Publish Package Release</span>
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Live Server Packages Table -->
        <div class="panel" style="min-width: 0;">
            <div class="panel-header" style="border-bottom: 1px solid var(--border); padding: 18px 24px;">
                <div class="panel-title" style="font-size: 15px; font-weight: 600;">Active Cloud Packages on Server</div>
            </div>
            <div style="overflow-x: auto; max-height: 380px;">
                <table style="width: 100%; border-collapse: collapse; text-align: left;">
                    <thead>
                        <tr style="border-bottom: 1px solid var(--border); background: var(--bg-surface-secondary); font-size: 11px; text-transform: uppercase; color: var(--text-muted);">
                            <th style="padding: 10px 16px;">Feature</th>
                            <th style="padding: 10px 16px;">File</th>
                            <th style="padding: 10px 16px;">SHA-256</th>
                            <th style="padding: 10px 16px;">Size</th>
                            <th style="padding: 10px 16px;">Active Release ID</th>
                            <th style="padding: 10px 16px;">Published</th>
                        </tr>
                    </thead>
                    <tbody>
                        {pkg_rows_html}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Release Changelog History -->
    <div class="panel" style="min-width: 0;">
        <div class="panel-header" style="border-bottom: 1px solid var(--border); padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div class="panel-title" style="font-size: 15px; font-weight: 600;">Release & Changelog Audit History</div>
            <form action="/admin/releases/clear" method="POST" onsubmit="return confirm('Are you sure you want to reset and clear all release history? iOS users will not receive past update prompts until a new package is uploaded.');" style="margin: 0;">
                <button type="submit" class="btn btn-outline btn-sm" style="color: #ef4444; border-color: rgba(239, 68, 68, 0.35); gap: 6px; padding: 5px 12px; font-size: 12px;">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                    <span>Clear / Reset History</span>
                </button>
            </form>
        </div>
        <div style="overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; text-align: left;">
                <thead>
                    <tr style="border-bottom: 1px solid var(--border); background: var(--bg-surface-secondary); font-size: 11px; text-transform: uppercase; color: var(--text-muted);">
                        <th style="padding: 12px 16px;">Time (NPT)</th>
                        <th style="padding: 12px 16px;">Package</th>
                        <th style="padding: 12px 16px;">Release ID</th>
                        <th style="padding: 12px 16px;">Content SHA-256</th>
                        <th style="padding: 12px 16px;">Changelog Notes</th>
                        <th style="padding: 12px 16px;">User Acks</th>
                    </tr>
                </thead>
                <tbody>
                    {rel_rows_html}
                </tbody>
            </table>
        </div>
    </div>
    """
    return HTMLResponse(render_layout("Releases & Patches", "Release Engine", content, active_tab="releases"))

@app.post("/admin/releases/clear")
async def admin_clear_releases_action(request: Request, db: AsyncSession = Depends(get_db)):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
    await db.execute(delete(PackageRelease))
    await db.execute(delete(UserReleaseAcknowledgment))
    await db.commit()
    return RedirectResponse(url="/admin/releases?msg=All+release+history+and+acknowledgments+cleared+successfully.", status_code=303)

@app.post("/admin/releases/upload")
async def admin_upload_release(
    request: Request,
    package_file: UploadFile = File(...),
    package_name: Optional[str] = Form(None),
    version_tag: Optional[str] = Form("v1.1"),
    release_notes: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)

    filename = package_file.filename
    if not filename.endswith(".3105"):
        return RedirectResponse(url="/admin/releases?err=Only+.3105+package+files+are+supported.", status_code=303)

    p_bytes = await package_file.read()
    if not p_bytes:
        return RedirectResponse(url="/admin/releases?err=Uploaded+file+is+empty.", status_code=303)

    p_name = package_name.strip() if (package_name and package_name.strip()) else normalize_package_name_from_filename(filename)

    try:
        rel_rec = await create_and_publish_release(
            filename=filename,
            package_name=p_name,
            package_bytes=p_bytes,
            release_notes=release_notes.strip(),
            version_tag=version_tag.strip() if version_tag else "v1.1",
            db=db
        )
        return RedirectResponse(url=f"/admin/releases?msg=Release+{rel_rec.release_id}+published+successfully!", status_code=303)
    except Exception as e:
        logger.error(f"[Admin Release Upload Error] {e}")
        return RedirectResponse(url=f"/admin/releases?err=Failed+to+publish+release:+{str(e)}", status_code=303)


# -------------------------------------------------------------
# 10. SERVER ENTRY POINT
# -------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("SERVER_PORT", os.getenv("PORT", "8000")))
    print(f"[*] {settings.APP_NAME} live on http://0.0.0.0:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
