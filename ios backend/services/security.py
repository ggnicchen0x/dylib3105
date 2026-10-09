import time
import math
from collections import defaultdict
from typing import Dict, List, Optional, Set
from fastapi import Request, HTTPException, status
from config import settings
from utils.crypto import verify_hmac_signature

# -------------------------------------------------------------
# DUAL-LAYER RATE LIMITER & 10-MINUTE TIMEOUT JAIL
# -------------------------------------------------------------
# Tracks timestamp history for sliding window: key -> [timestamp, ...]
attempt_history: Dict[str, List[float]] = defaultdict(list)

# Tracks active lockouts: key -> lockout_expiration_epoch
active_lockouts: Dict[str, float] = {}

# Anti-replay signature cache with expiration: signature -> seen_epoch
seen_signatures: Dict[str, float] = {}

def get_real_client_ip(request: Request) -> str:
    """
    Safely resolves real client IP behind Bot-Hosting, Cloudflare, or reverse proxy.
    """
    # 1. Cloudflare header
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
        
    # 2. X-Forwarded-For (first IP in chain is original client)
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        client_candidate = xff.split(",")[0].strip()
        if client_candidate:
            return client_candidate
            
    # 3. X-Real-IP
    x_real = request.headers.get("X-Real-IP")
    if x_real:
        return x_real.strip()
        
    # 4. Fallback to direct client host
    if request.client and request.client.host:
        return request.client.host
        
    return "127.0.0.1"

def check_and_enforce_rate_limit(client_ip: str, device_hash: Optional[str] = None):
    """
    Enforces 5 attempts per 60s rule.
    If exceeded, locks the client (both IP and HWID) out for 10 minutes (600s).
    """
    now = time.time()
    keys_to_check = [f"ip:{client_ip}"]
    if device_hash:
        keys_to_check.append(f"hwid:{device_hash}")
        
    # 1. Check if currently under active lockout
    for key in keys_to_check:
        lockout_expiry = active_lockouts.get(key)
        if lockout_expiry and now < lockout_expiry:
            remaining_seconds = int(math.ceil(lockout_expiry - now))
            minutes = remaining_seconds // 60
            seconds = remaining_seconds % 60
            time_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Spam detected: Do not repeatedly tap login. You have been timed out for 10 minutes. Please wait {time_str} before retrying."
            )
        elif lockout_expiry and now >= lockout_expiry:
            # Lockout expired, clean up
            active_lockouts.pop(key, None)
            attempt_history.pop(key, None)

    # 2. Evaluate sliding window
    window_start = now - settings.SPAM_WINDOW_SECONDS
    for key in keys_to_check:
        # Prune older attempts
        history = [t for t in attempt_history[key] if t > window_start]
        history.append(now)
        attempt_history[key] = history
        
        # Check if limit exceeded (5 attempts in 1 min)
        if len(history) > settings.SPAM_MAX_ATTEMPTS:
            lockout_until = now + settings.SPAM_LOCKOUT_SECONDS
            # Apply lockout to both IP and HWID
            for k in keys_to_check:
                active_lockouts[k] = lockout_until
                
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Spam detected: Do not repeatedly tap login. You have been timed out for 10 minutes. Please wait 10m 00s before retrying."
            )

def verify_request_integrity(
    timestamp: int,
    license_key: str,
    device_hash: str,
    signature: str
):
    """
    Validates anti-replay timestamp (within 60s), nonce uniqueness, and HMAC signature.
    """
    current_time = int(time.time())
    
    # 1. Anti-replay clock drift check (max 60 seconds skew)
    if abs(current_time - timestamp) > 60:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request timestamp expired or out of synchronization (Anti-Replay Triggered)."
        )
    
    # 2. Nonce/Signature replay attack prevention
    # Prune old signatures (> 120s old)
    stale_cutoff = current_time - 120
    stale_sigs = [sig for sig, seen in seen_signatures.items() if seen < stale_cutoff]
    for sig in stale_sigs:
        seen_signatures.pop(sig, None)
        
    if signature in seen_signatures:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Duplicate request detected: Signature replay blocked."
        )
    
    # 3. Cryptographic HMAC validation
    payload_to_verify = f"{license_key}:{device_hash}:{timestamp}"
    if not verify_hmac_signature(payload_to_verify, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid cryptographic request signature (HMAC Tamper Triggered)."
        )
        
    seen_signatures[signature] = float(current_time)
