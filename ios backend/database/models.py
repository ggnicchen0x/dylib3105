import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey, Numeric
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.future import select
from config import settings

Base = declarative_base()

def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

def is_license_expired(lic) -> bool:
    if not lic:
        return False
    if lic.status == "expired":
        return True
    if lic.expires_at is not None and lic.expires_at <= utc_now():
        return True
    return False

class License(Base):
    __tablename__ = "licenses"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(64), unique=True, index=True, nullable=False)
    status = Column(String(20), default="active", index=True) # "active", "banned", "expired", "revoked"
    bound_device_hash = Column(String(128), nullable=True, index=True)
    duration_days = Column(Integer, nullable=True, default=None) # Number of days validity, countdown starts on first use
    created_at = Column(DateTime, default=utc_now)
    activated_at = Column(DateTime, nullable=True) # Set when client binds device on first login
    expires_at = Column(DateTime, nullable=True) # Calculated as activated_at + duration_days upon first activation; None = Lifetime
    notes = Column(String(255), default="Standard User Key")
    
    # Reseller & Customer association
    seller_id = Column(Integer, ForeignKey("resellers.id"), nullable=True, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True, index=True)
    generated_by = Column(String(50), default="admin") # "admin" or "reseller"
    pricing_tier = Column(String(20), nullable=True) # e.g. "7d", "15d", "30d"
    
    devices = relationship("Device", back_populates="license", uselist=False)
    reseller = relationship("Reseller", back_populates="licenses", foreign_keys=[seller_id])
    customer = relationship("Customer", back_populates="licenses", foreign_keys=[customer_id])

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
    app_version = Column(String(32), default="1.1.4")
    force_update = Column(Boolean, default=False)
    maintenance_message = Column(String(255), default="Server maintenance is currently in progress. Please check Discord announcements for status updates: https://discord.gg/KPJzd42rme")
    release_notes = Column(Text, default="Official Release v1.1.4: Enhanced security protocols, updated dynamic cloud patches, and ultra-smooth engine performance.")
    download_url = Column(String(255), default="https://github.com/nicchen0xf/Swift-ios/releases/download/v1.1.4/ByteExternal_V1.1.4.ipa")
    updated_at = Column(DateTime, default=utc_now)


class PackageRelease(Base):
    __tablename__ = "package_releases"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    release_id = Column(String(64), unique=True, index=True, nullable=False) # e.g. rel_7a8f9c12
    package_name = Column(String(100), index=True, nullable=False) # e.g. "Avatar Drag"
    filename = Column(String(100), index=True, nullable=False) # e.g. "Avatar Drag.3105"
    file_sha256 = Column(String(64), index=True, nullable=False)
    file_size = Column(Integer, default=0)
    version_tag = Column(String(32), default="v1.0")
    changed_features = Column(Text, nullable=True) # JSON list or notes
    release_notes = Column(Text, nullable=False) # "What's New" bullets/description
    is_published = Column(Boolean, default=True, index=True)
    is_announcement = Column(Boolean, default=False, index=True) # True only when admin publishes an active update notice
    created_at = Column(DateTime, default=utc_now)
    published_at = Column(DateTime, default=utc_now)

class UserReleaseAcknowledgment(Base):
    __tablename__ = "user_release_acknowledgments"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    release_id = Column(String(64), index=True, nullable=False)
    device_hash = Column(String(128), index=True, nullable=False)
    license_key = Column(String(64), nullable=True, index=True)
    seen_at = Column(DateTime, default=utc_now)

class Reseller(Base):
    __tablename__ = "resellers"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    display_name = Column(String(100), nullable=False)
    email = Column(String(120), nullable=True)
    status = Column(String(20), default="active", index=True) # "active", "suspended", "inactive"
    credit_balance = Column(Numeric(12, 4), default=0.0000, nullable=False)
    created_at = Column(DateTime, default=utc_now)
    last_login_at = Column(DateTime, nullable=True)
    notes = Column(String(255), nullable=True)
    created_by = Column(String(50), default="admin")
    
    customers = relationship("Customer", back_populates="reseller", cascade="all, delete-orphan")
    ledger_entries = relationship("CreditLedger", back_populates="reseller", cascade="all, delete-orphan")
    licenses = relationship("License", back_populates="reseller", foreign_keys="[License.seller_id]")

class Customer(Base):
    __tablename__ = "customers"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    seller_id = Column(Integer, ForeignKey("resellers.id"), nullable=False, index=True)
    customer_code = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    contact = Column(String(120), nullable=True) # Discord, Telegram, or email
    status = Column(String(20), default="active", index=True) # "active", "suspended"
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    
    reseller = relationship("Reseller", back_populates="customers")
    licenses = relationship("License", back_populates="customer", foreign_keys="[License.customer_id]")

class CreditLedger(Base):
    __tablename__ = "credit_ledger"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    transaction_id = Column(String(64), unique=True, index=True, nullable=False)
    seller_id = Column(Integer, ForeignKey("resellers.id"), nullable=False, index=True)
    transaction_type = Column(String(40), nullable=False, index=True) # "ADMIN_ALLOCATE", "ADMIN_DEDUCT", "KEY_GENERATE", "REVERSAL", "ADMIN_CORRECTION"
    amount = Column(Numeric(12, 4), nullable=False) # signed: e.g. +10.0000 or -0.5000
    balance_before = Column(Numeric(12, 4), nullable=False)
    balance_after = Column(Numeric(12, 4), nullable=False)
    description = Column(String(255), nullable=False)
    related_key = Column(String(64), nullable=True, index=True)
    related_customer_id = Column(Integer, nullable=True)
    initiated_by = Column(String(64), nullable=False) # e.g. "admin" or seller username
    timestamp = Column(DateTime, default=utc_now, index=True)
    status = Column(String(20), default="COMPLETED", index=True) # "COMPLETED", "REVERSED"
    idempotency_key = Column(String(128), nullable=True, index=True)
    correlation_id = Column(String(64), nullable=True, index=True)
    
    reseller = relationship("Reseller", back_populates="ledger_entries")

class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    idempotency_key = Column(String(128), unique=True, index=True, nullable=False)
    seller_id = Column(Integer, nullable=False, index=True)
    endpoint = Column(String(100), nullable=False)
    response_status = Column(Integer, nullable=False)
    response_body = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now)

# Async engine & session
engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

def preflight_database_health():
    import sqlite3, shutil, time, os
    db_url = settings.DATABASE_URL
    if "sqlite" not in db_url:
        return
    path_part = db_url.split(":///")[-1] if ":///" in db_url else ""
    db_path = path_part.lstrip("./") if path_part.startswith("./") else path_part
    if not db_path:
        db_path = "auth_gateway.db"

    is_corrupt = False
    if os.path.exists(db_path):
        con = None
        try:
            con = sqlite3.connect(db_path, timeout=5.0)
            res = con.execute("PRAGMA quick_check").fetchone()
            if not (res and res[0] == "ok"):
                is_corrupt = True
        except Exception:
            is_corrupt = True
        finally:
            if con:
                try: con.close()
                except Exception: pass

    if is_corrupt:
        broken_backup = f"{db_path}.malformed_{int(time.time())}"
        try: shutil.copy2(db_path, broken_backup)
        except Exception: pass
        for ext in ["", "-wal", "-shm"]:
            f = db_path + ext
            if os.path.exists(f):
                try: os.remove(f)
                except Exception: pass
        sql_dump = "auth_gateway.sql"
        if os.path.exists(sql_dump):
            try:
                con = sqlite3.connect(db_path)
                with open(sql_dump, "r", encoding="utf-8") as f:
                    con.executescript(f.read())
                con.execute("PRAGMA journal_mode = DELETE;")
                con.execute("VACUUM;")
                con.close()
            except Exception:
                pass

async def init_db():
    preflight_database_health()
    async with engine.begin() as conn:
        from sqlalchemy import text
        try:
            await conn.execute(text("PRAGMA journal_mode=WAL;"))
            await conn.execute(text("PRAGMA synchronous=NORMAL;"))
        except Exception:
            pass
        await conn.run_sync(Base.metadata.create_all)
        try:
            await conn.execute(text("DROP INDEX IF EXISTS ix_licenses_bound_device_hash"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE licenses ADD COLUMN duration_days INTEGER DEFAULT NULL"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE licenses ADD COLUMN seller_id INTEGER DEFAULT NULL"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE licenses ADD COLUMN customer_id INTEGER DEFAULT NULL"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE licenses ADD COLUMN generated_by VARCHAR(50) DEFAULT 'admin'"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE licenses ADD COLUMN pricing_tier VARCHAR(20) DEFAULT NULL"))
        except Exception:
            pass
        try:
            await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_licenses_seller_id ON licenses(seller_id)"))
            await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_licenses_customer_id ON licenses(customer_id)"))
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
            await conn.execute(text("ALTER TABLE system_config ADD COLUMN release_notes TEXT DEFAULT 'Official Release v1.1.3'"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE system_config ADD COLUMN download_url VARCHAR(255) DEFAULT 'https://github.com/nicchen0xf/Swift-ios/releases'"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE system_config ADD COLUMN updated_at DATETIME"))
        except Exception:
            pass
        try:
            await conn.execute(text("ALTER TABLE devices ADD COLUMN public_key TEXT"))
        except Exception:
            pass
        try:
            await conn.execute(text("DELETE FROM package_releases WHERE release_notes LIKE '%baseline%' OR version_tag = 'v1.0' OR release_notes = 'Official baseline release.'"))
        except Exception:
            pass

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(SystemConfig))
        config = result.scalars().first()
        if not config:
            config = SystemConfig(
                app_status="ACTIVE",
                app_version="1.1.4",
                force_update=False,
                updated_at=utc_now()
            )
            session.add(config)
            await session.commit()

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
