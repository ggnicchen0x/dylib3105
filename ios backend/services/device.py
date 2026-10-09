import datetime
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
from database.models import Device, License, AuditLog

async def get_or_register_device(
    db: AsyncSession,
    device_hash: str,
    device_name: str,
    device_model: str,
    os_version: str,
    client_ip: str
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
            first_seen=datetime.datetime.utcnow(),
            last_seen=datetime.datetime.utcnow()
        )
        db.add(device)
        await db.commit()
        await db.refresh(device)
    else:
        device.last_seen = datetime.datetime.utcnow()
        device.ip_address = client_ip
        device.device_name = device_name
        await db.commit()
        await db.refresh(device)
        
    if device.is_banned:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Device permanently banned: {device.ban_reason or 'Security Violation'}"
        )
        
    return device
