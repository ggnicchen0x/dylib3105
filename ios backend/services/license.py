import secrets
import string
import datetime
import logging
from typing import Optional, Any, Union
from sqlalchemy.future import select
from sqlalchemy import update, func
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
from database.models import License, Device, AuditLog, utc_now, is_license_expired
from utils.helpers import send_discord_alert, mask_license_key

logger = logging.getLogger("auth_gateway")

def generate_random_license_key(prefix: str = "BYTE") -> str:
    """
    Format: BYTE-XXXX-XXXX-XXXX (16 alphanumeric characters)
    """
    clean_prefix = (prefix or "BYTE").strip().upper()
    charset = string.ascii_uppercase + string.digits
    parts = [''.join(secrets.choice(charset) for _ in range(4)) for _ in range(3)]
    return f"{clean_prefix}-{'-'.join(parts)}"

async def activate_or_verify_license(
    db: AsyncSession,
    license_key: str,
    device: Any,
    client_ip: str
) -> License:
    device_hwid = device.device_hash if hasattr(device, "device_hash") else str(device)
    clean_k = license_key.strip().upper()
    result = await db.execute(select(License).where(func.upper(License.key) == clean_k))
    lic = result.scalars().first()
    
    if not lic:
        log = AuditLog(
            action="LOGIN_FAILED_INVALID_KEY",
            ip_address=client_ip,
            device_hash=device_hwid,
            license_key=mask_license_key(license_key),
            details="Attempted login with non-existent license key."
        )
        db.add(log)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid license key provided."
        )
        
    if lic.status == "banned":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This license key has been permanently blacklisted by administration."
        )
    elif lic.status == "revoked":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This license key has been revoked."
        )
        
    if is_license_expired(lic):
        lic.status = "expired"
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="License key has expired."
        )
        
    # Strict Hardware Binding with Atomic Race-Condition Protection
    if lic.bound_device_hash is None:
        lic_id = lic.id
        device_hwid = device.device_hash if hasattr(device, "device_hash") else str(device)
        now = utc_now()

        calc_activated_at = lic.activated_at or now
        calc_expires_at = lic.expires_at
        if calc_expires_at is None and getattr(lic, "duration_days", None) and lic.duration_days > 0:
            calc_expires_at = calc_activated_at + datetime.timedelta(days=lic.duration_days)

        try:
            from sqlalchemy import text
            await db.execute(
                text("UPDATE licenses SET bound_device_hash = NULL WHERE bound_device_hash = :hwid AND id != :lic_id"),
                {"hwid": device_hwid, "lic_id": lic_id}
            )
        except Exception:
            pass

        # Atomic conditional update
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
            # Race condition detected: another request claimed this license between select and update!
            await db.rollback()
            res_check = await db.execute(select(License).where(License.id == lic_id))
            refreshed_lic = res_check.scalars().first()
            if refreshed_lic and refreshed_lic.bound_device_hash != device_hwid:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="License key is locked to another hardware device. Key sharing is strictly prohibited."
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
        dev_os = getattr(device, "os_version", "iOS")
        
        log = AuditLog(
            action="LICENSE_ACTIVATED",
            ip_address=client_ip,
            device_hash=device_hwid,
            license_key=mask_license_key(license_key),
            details=f"License activated & bound to {dev_name} ({dev_model})"
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
        
        await send_discord_alert(
            title="Key Activated & Hardware Bound",
            description=f"Key `{mask_license_key(license_key)}` was successfully locked to a new device.",
            color=0x4CAF50,
            fields=[
                {"name": "Device Name", "value": dev_name, "inline": True},
                {"name": "Device Model", "value": dev_model, "inline": True},
                {"name": "OS Version", "value": dev_os, "inline": True},
                {"name": "HWID Hash", "value": f"`{device_hwid[:16]}...`", "inline": False},
                {"name": "IP Address", "value": client_ip, "inline": True},
            ]
        )
    else:
        if lic.bound_device_hash != device_hwid:
            dev_name = getattr(device, "device_name", "Device")
            dev_model = getattr(device, "device_model", "iOS Device")
            log = AuditLog(
                action="HWID_MISMATCH_BLOCKED",
                ip_address=client_ip,
                device_hash=device_hwid,
                license_key=mask_license_key(license_key),
                details="Unauthorized device attempted to reuse key bound to another device."
            )
            db.add(log)
            await db.commit()
            
            await send_discord_alert(
                title="⚠️ Unauthorized Key Sharing Attempt",
                description=f"An unauthorized device attempted to log into bound key `{mask_license_key(license_key)}`.",
                color=0xF44336,
                fields=[
                    {"name": "Attempting Device", "value": f"{dev_name} ({dev_model})", "inline": True},
                    {"name": "Attempting HWID", "value": f"`{device_hwid[:16]}...`", "inline": True},
                    {"name": "IP Address", "value": client_ip, "inline": True}
                ]
            )
            
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="License key is locked to another hardware device. Key sharing is strictly prohibited."
            )
            
    return lic
