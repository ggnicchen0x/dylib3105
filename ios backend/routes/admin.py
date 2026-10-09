import io
import csv
import secrets
import datetime
import logging
from pydantic import BaseModel, Field
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from jose import jwt, JWTError

from database.models import get_db, License, Device, AuditLog, utc_now, is_license_expired
from services.license import generate_random_license_key
from utils.helpers import mask_license_key
from config import settings

logger = logging.getLogger("auth_gateway")
router = APIRouter(prefix="/api/v1/admin", tags=["Admin Management"])

revoked_admin_tokens = set()

def verify_admin_session(request: Request):
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        if token in revoked_admin_tokens:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin token has been revoked.")
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            if payload.get("sub") == "admin":
                return True
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin session token.")
            
    header_key = request.headers.get("x-admin-key")
    if header_key:
        if settings.ALLOW_LEGACY_ADMIN_API_KEY and secrets.compare_digest(header_key, settings.ADMIN_API_KEY):
            logger.warning("[SECURITY AUDIT] Legacy x-admin-key header utilized for admin operation.")
            return True
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized: Invalid or disabled Admin API Key.")

    token = request.cookies.get(settings.ADMIN_SESSION_COOKIE)
    if token and token not in revoked_admin_tokens:
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            if payload.get("sub") == "admin":
                return True
        except JWTError:
            pass

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required: Valid admin session missing.")

class KeyGenRequest(BaseModel):
    count: int = Field(default=1, ge=1, le=500)
    duration_days: Optional[int] = Field(default=None, ge=1, le=3650)
    prefix: str = Field(default="BYTE", max_length=16)
    notes: Optional[str] = Field(default="Customer License", max_length=255)

class ExtendKeyRequest(BaseModel):
    license_key: str = Field(..., min_length=8, max_length=64)
    add_days: int = Field(default=30, ge=0, le=3650)

class BanDeviceRequest(BaseModel):
    device_hash: str = Field(..., min_length=16, max_length=128)
    reason: str = Field(default="Violated terms / cracked", max_length=255)

class ResetHWIDRequest(BaseModel):
    license_key: str = Field(..., min_length=8, max_length=64)
    reason: str = Field(default="Admin approved device transfer", max_length=255)

@router.post("/generate-keys", dependencies=[Depends(verify_admin_session)])
async def generate_keys(req: KeyGenRequest, db: AsyncSession = Depends(get_db)):
    created_keys = []
    duration_days = req.duration_days if req.duration_days and req.duration_days > 0 else None
        
    for _ in range(req.count):
        raw_key = generate_random_license_key(prefix=req.prefix)
        lic = License(
            key=raw_key,
            status="active",
            bound_device_hash=None,
            duration_days=duration_days,
            created_at=utc_now(),
            activated_at=None,
            expires_at=None,
            notes=req.notes or "Admin Generated"
        )
        db.add(lic)
        created_keys.append(raw_key)
        
    await db.commit()
    return {
        "success": True,
        "count": len(created_keys),
        "duration": f"{duration_days} days (starts upon activation)" if duration_days else "LIFETIME",
        "keys": created_keys
    }

@router.get("/licenses", dependencies=[Depends(verify_admin_session)])
async def list_licenses(limit: int = 50, filter: str = "All", db: AsyncSession = Depends(get_db)):
    limit = max(1, min(limit, 500))
    result = await db.execute(select(License).order_by(License.created_at.desc()).limit(limit))
    licenses = result.scalars().all()
    
    out = []
    for lic in licenses:
        expired = is_license_expired(lic)
        computed_status = "expired" if expired and lic.status != "banned" else lic.status
        
        if filter == "Active" and (computed_status != "active" or lic.bound_device_hash is None):
            continue
        elif filter == "Unused" and (computed_status != "active" or lic.bound_device_hash is not None):
            continue
        elif filter == "Expired" and not expired:
            continue
        elif filter == "Banned" and lic.status != "banned":
            continue
            
        out.append({
            "id": lic.id,
            "key": lic.key,
            "status": computed_status,
            "bound_device_hash": lic.bound_device_hash,
            "duration_days": lic.duration_days,
            "created_at": lic.created_at.isoformat() if lic.created_at else None,
            "activated_at": lic.activated_at.isoformat() if lic.activated_at else None,
            "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
            "notes": lic.notes
        })
    return out

@router.post("/extend-key", dependencies=[Depends(verify_admin_session)])
async def extend_license_validity(req: ExtendKeyRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(License).where(License.key == req.license_key.strip()))
    lic = result.scalars().first()
    if not lic:
        raise HTTPException(status_code=404, detail="License key not found.")
        
    now = utc_now()
    if req.add_days == 0:
        lic.expires_at = None
        lic.duration_days = None
        if lic.status == "expired":
            lic.status = "active"
        msg = f"License converted to Lifetime (No Expiry)."
    else:
        if is_license_expired(lic):
            lic.expires_at = now + datetime.timedelta(days=req.add_days)
            lic.status = "active"
            msg = f"License renewed for {req.add_days} days starting now."
        elif lic.activated_at is None:
            current_duration = lic.duration_days or 0
            lic.duration_days = current_duration + req.add_days
            msg = f"License initial duration extended by {req.add_days} days (total {lic.duration_days} days)."
        else:
            base_time = lic.expires_at if lic.expires_at and lic.expires_at > now else now
            lic.expires_at = base_time + datetime.timedelta(days=req.add_days)
            lic.status = "active"
            msg = f"License validity extended by {req.add_days} days."

    log = AuditLog(
        action="ADMIN_EXTEND_LICENSE",
        license_key=mask_license_key(lic.key),
        details=msg
    )
    db.add(log)
    await db.commit()
    
    return {
        "success": True,
        "message": msg,
        "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
        "duration_days": lic.duration_days,
        "status": lic.status
    }

@router.get("/export", dependencies=[Depends(verify_admin_session)])
async def export_licenses(format: str = "csv", filter: str = "All", db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(License).order_by(License.created_at.desc()))
    all_keys = result.scalars().all()
    
    filtered = []
    for k in all_keys:
        expired = is_license_expired(k)
        computed_status = "expired" if expired and k.status != "banned" else k.status
        if filter == "Active" and (computed_status != "active" or k.bound_device_hash is None):
            continue
        elif filter == "Unused" and (computed_status != "active" or k.bound_device_hash is not None):
            continue
        elif filter == "Expired" and not expired:
            continue
        elif filter == "Banned" and k.status != "banned":
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
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="licenses_{filter.lower()}_{timestamp}.csv"'}
        )

@router.post("/reset-hwid", dependencies=[Depends(verify_admin_session)])
async def reset_license_hwid(req: ResetHWIDRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(License).where(License.key == req.license_key.strip()))
    lic = result.scalars().first()
    if not lic:
        raise HTTPException(status_code=404, detail="License key not found.")
        
    old_hwid = lic.bound_device_hash
    lic.bound_device_hash = None
    if lic.status != "banned" and not is_license_expired(lic):
        lic.status = "active"
    
    log = AuditLog(
        action="ADMIN_RESET_HWID",
        license_key=mask_license_key(lic.key),
        device_hash=old_hwid,
        details=f"HWID unlinked by admin. Reason: {req.reason.strip()}"
    )
    db.add(log)
    await db.commit()
    
    return {"success": True, "message": f"HWID lock removed from {mask_license_key(req.license_key)}. Key is now ready for re-binding."}

@router.post("/ban-device", dependencies=[Depends(verify_admin_session)])
async def ban_device(req: BanDeviceRequest, db: AsyncSession = Depends(get_db)):
    clean_hwid = req.device_hash.strip()
    result = await db.execute(select(Device).where(Device.device_hash == clean_hwid))
    device = result.scalars().first()
    if not device:
        device = Device(
            device_hash=clean_hwid,
            is_banned=True,
            ban_reason=req.reason.strip()
        )
        db.add(device)
    else:
        device.is_banned = True
        device.ban_reason = req.reason.strip()
        
    await db.commit()
    return {"success": True, "message": f"Device {clean_hwid[:16]}... has been permanently banned."}

@router.get("/logs", dependencies=[Depends(verify_admin_session)])
async def get_logs(limit: int = 100, db: AsyncSession = Depends(get_db)):
    limit = max(1, min(limit, 500))
    result = await db.execute(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit))
    logs = result.scalars().all()
    return logs

@router.post("/delete-expired", dependencies=[Depends(verify_admin_session)])
async def delete_expired_licenses(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(License))
    all_keys = res.scalars().all()
    expired_keys = [k for k in all_keys if is_license_expired(k) and k.status != "banned"]
    
    deleted_count = len(expired_keys)
    if deleted_count > 0:
        expired_key_strings = [k.key for k in expired_keys]
        try:
            from database.models import SessionToken
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
            details=f"Admin bulk-deleted {deleted_count} expired license keys from database."
        )
        db.add(log)
        await db.commit()
        
    return {
        "success": True,
        "count": deleted_count,
        "message": f"Successfully deleted {deleted_count} expired license keys."
    }
