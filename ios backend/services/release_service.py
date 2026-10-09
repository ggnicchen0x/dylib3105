import os
import hashlib
import secrets
import json
import logging
from typing import Optional, Dict, Any, List
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc

from database.models import PackageRelease, UserReleaseAcknowledgment, utc_now

logger = logging.getLogger("release_service")

STORAGE_PATCHES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "storage", "patches"))

def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def normalize_package_name_from_filename(filename: str) -> str:
    base = os.path.basename(filename)
    if base.lower().endswith(".3105"):
        base = base[:-5]
    return base.replace("_", " ").strip()

async def get_latest_release_for_filename(filename: str, db: AsyncSession) -> Optional[PackageRelease]:
    query = (
        select(PackageRelease)
        .where(PackageRelease.filename == filename.strip())
        .order_by(desc(PackageRelease.created_at))
    )
    result = await db.execute(query)
    return result.scalars().first()

async def check_package_diff(filename: str, new_bytes: bytes, db: AsyncSession) -> Dict[str, Any]:
    """Inspects an uploaded package to see if its content (SHA-256) changed vs the latest recorded release."""
    new_hash = calculate_sha256(new_bytes)
    new_size = len(new_bytes)
    package_name = normalize_package_name_from_filename(filename)
    
    latest_release = await get_latest_release_for_filename(filename, db)
    
    if not latest_release:
        return {
            "is_new": True,
            "is_first_release": True,
            "filename": filename,
            "package_name": package_name,
            "new_hash": new_hash,
            "new_size": new_size,
            "previous_hash": None,
            "previous_release_id": None,
            "previous_version": None
        }
        
    is_changed = (latest_release.file_sha256.lower() != new_hash.lower())
    return {
        "is_new": is_changed,
        "is_first_release": False,
        "filename": filename,
        "package_name": package_name,
        "new_hash": new_hash,
        "new_size": new_size,
        "previous_hash": latest_release.file_sha256,
        "previous_release_id": latest_release.release_id,
        "previous_version": latest_release.version_tag
    }

async def create_and_publish_release(
    filename: str,
    package_name: str,
    package_bytes: bytes,
    release_notes: str,
    changed_features: Optional[List[str]] = None,
    version_tag: Optional[str] = None,
    db: Optional[AsyncSession] = None
) -> PackageRelease:
    """Saves the package binary to disk and records a unique release ID in DB."""
    if not db:
        raise ValueError("Database session is required")
        
    os.makedirs(STORAGE_PATCHES_DIR, exist_ok=True)
    target_path = os.path.join(STORAGE_PATCHES_DIR, os.path.basename(filename.strip()))
    
    # 1. Write file to disk
    with open(target_path, "wb") as f:
        f.write(package_bytes)
        
    file_hash = calculate_sha256(package_bytes)
    file_size = len(package_bytes)
    
    # 2. Check for duplicate exact hash in active releases
    existing_same_hash = await db.execute(
        select(PackageRelease)
        .where(PackageRelease.filename == filename.strip())
        .where(PackageRelease.file_sha256 == file_hash)
    )
    dup = existing_same_hash.scalars().first()
    if dup:
        logger.info(f"[Release] Re-publishing existing exact binary for {filename} (Release ID: {dup.release_id})")
        # Update notes/version if provided
        dup.release_notes = release_notes.strip()
        if version_tag:
            dup.version_tag = version_tag.strip()
        dup.published_at = utc_now()
        await db.commit()
        await db.refresh(dup)
        return dup

    # 3. Create fresh unique release record
    unique_release_id = f"rel_{secrets.token_hex(6)}"
    clean_version = version_tag.strip() if version_tag else f"v{secrets.token_hex(2)}"
    
    release_rec = PackageRelease(
        release_id=unique_release_id,
        package_name=package_name.strip(),
        filename=os.path.basename(filename.strip()),
        file_sha256=file_hash,
        file_size=file_size,
        version_tag=clean_version,
        changed_features=json.dumps(changed_features) if changed_features else None,
        release_notes=release_notes.strip(),
        is_published=True,
        is_announcement=True, # Active admin update notice
        created_at=utc_now(),
        published_at=utc_now()
    )
    db.add(release_rec)
    await db.commit()
    await db.refresh(release_rec)

    return release_rec

async def get_unseen_releases_for_device(device_hash: str, db: AsyncSession) -> List[Dict[str, Any]]:
    """Returns all published package announcements that have NOT yet been acknowledged by this device."""
    clean_dh = device_hash.strip()
    
    # Fetch acknowledged release IDs for this device
    ack_query = select(UserReleaseAcknowledgment.release_id).where(UserReleaseAcknowledgment.device_hash == clean_dh)
    ack_res = await db.execute(ack_query)
    seen_ids = set(ack_res.scalars().all())
    
    # Fetch published announcements only (suppresses baseline seeded files from popping up)
    rel_query = (
        select(PackageRelease)
        .where(PackageRelease.is_published == True)
        .where(PackageRelease.is_announcement == True)
        .order_by(desc(PackageRelease.published_at))
    )
    rel_res = await db.execute(rel_query)
    all_releases = rel_res.scalars().all()
    
    unseen: List[Dict[str, Any]] = []
    # Deduplicate by filename to only show the single latest release per package if multiple unread
    seen_filenames = set()
    
    for r in all_releases:
        if r.release_id not in seen_ids and r.filename not in seen_filenames:
            seen_filenames.add(r.filename)
            features = []
            if r.changed_features:
                try:
                    features = json.loads(r.changed_features)
                except Exception:
                    features = [r.changed_features]
            unseen.append({
                "release_id": r.release_id,
                "package_name": r.package_name,
                "filename": r.filename,
                "version_tag": r.version_tag,
                "release_notes": r.release_notes,
                "changed_features": features,
                "file_sha256": r.file_sha256,
                "published_at": r.published_at.isoformat() if r.published_at else ""
            })
            
    return unseen

async def record_user_acknowledgment(
    device_hash: str,
    release_id: str,
    license_key: Optional[str],
    db: AsyncSession
) -> bool:
    """Marks a release as seen/acknowledged by a device hash so it never appears again."""
    clean_dh = device_hash.strip()
    clean_rid = release_id.strip()
    
    # Check if already recorded
    existing = await db.execute(
        select(UserReleaseAcknowledgment)
        .where(UserReleaseAcknowledgment.device_hash == clean_dh)
        .where(UserReleaseAcknowledgment.release_id == clean_rid)
    )
    if existing.scalars().first():
        return True
        
    ack = UserReleaseAcknowledgment(
        release_id=clean_rid,
        device_hash=clean_dh,
        license_key=license_key.strip() if license_key else None,
        seen_at=utc_now()
    )
    db.add(ack)
    await db.commit()
    return True
