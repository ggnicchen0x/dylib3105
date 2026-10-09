import os
from typing import List, Optional, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    APP_NAME: str = "BYTE IOS Admin Panel"
    VERSION: str = "2.1.0"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() in ("true", "1")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
    
    HOST: str = "0.0.0.0"
    PORT: int = int(os.getenv("SERVER_PORT", os.getenv("PORT", "8000")))
    
    # Cryptographic keys
    SECRET_KEY: str = os.getenv("SECRET_KEY", "3105_SEC_KEY_e4b0546a57c844ddb94cdbd2e2393df1_PROD")
    HMAC_SECRET: str = os.getenv("HMAC_SECRET", "3105_HMAC_SIG_k9823hjd8923hjksdf78234")
    ADMIN_API_KEY: str = os.getenv("ADMIN_API_KEY", "3105_ADMIN_ROOT_9021839012389")
    ALLOW_LEGACY_ADMIN_API_KEY: bool = os.getenv("ALLOW_LEGACY_ADMIN_API_KEY", "true").lower() in ("true", "1")
    
    # Admin Credentials: username 'nicchen', password '9810'
    ADMIN_USER: str = os.getenv("ADMIN_USER", "nicchen")
    ADMIN_USER_HASH: str = os.getenv("ADMIN_USER_HASH", "44bc98df17fb92d3ca75f4d6774e773c9f45078b800834a991d6cfe38af5925e") # SHA-256 for "nicchen"
    ADMIN_PASS_HASH: str = os.getenv("ADMIN_PASS_HASH", "a6ca3fb6bc4695ee482532faa4c0a999f3dd06ecb62de10490b5b0da096e7a01") # SHA-256 for "9810"
    ADMIN_PBKDF2_PASS_HASH: Optional[str] = os.getenv("ADMIN_PBKDF2_PASS_HASH", None)
    
    # Admin Brute Force & Session Throttling
    ADMIN_MAX_FAILED_ATTEMPTS: int = 5
    ADMIN_LOCKOUT_SECONDS: int = 900 # 15 minutes
    
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 120
    ADMIN_SESSION_COOKIE: str = "auth_admin_session_3105"
    ADMIN_COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() in ("true", "1")
    
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./auth_gateway.db")
    DISCORD_WEBHOOK_URL: str = os.getenv("DISCORD_WEBHOOK_URL", "")
    
    # Public API Spam / Rate Limiting Controls
    SPAM_MAX_ATTEMPTS: int = 5
    SPAM_WINDOW_SECONDS: int = 60
    SPAM_LOCKOUT_SECONDS: int = 600
    
    RATE_LIMIT_VALIDATE_MAX: int = 60 # per minute
    RATE_LIMIT_PATCH_FETCH_MAX: int = 15 # per minute
    MAX_REQUEST_BODY_BYTES: int = 1024 * 1024 # 1 MB limit
    
    # Protocol Versioning & Retirement
    ENABLE_V1_PROTOCOL: bool = os.getenv("ENABLE_V1_PROTOCOL", "true").lower() in ("true", "1")
    
    # Reverse Proxy & Header Trust Controls
    TRUST_PROXY_HEADERS: bool = os.getenv("TRUST_PROXY_HEADERS", "true").lower() in ("true", "1")
    TRUSTED_PROXIES: Union[List[str], str] = ["127.0.0.1", "::1", "testserver"]
    
    # Redis / Distributed Cache (Optional, documented fallback to in-memory)
    REDIS_URL: Optional[str] = os.getenv("REDIS_URL", None)

    # Allowed origins for CORS (Admin Panel)
    ALLOWED_ORIGINS: Union[List[str], str] = ["http://localhost:8000", "http://127.0.0.1:8000"]

    @field_validator("TRUSTED_PROXIES", "ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_comma_separated_list(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    model_config = SettingsConfigDict(env_file=".env", extra="allow")

    def validate_production_secrets(self):
        """Enforces fail-closed validation if deployed in production mode."""
        if self.ENVIRONMENT in ("production", "strict_production"):
            insecure_defaults = [
                "3105_SEC_KEY_e4b0546a57c844ddb94cdbd2e2393df1_PROD",
                "3105_ADMIN_ROOT_9021839012389"
            ]
            if not self.SECRET_KEY or self.SECRET_KEY in insecure_defaults or len(self.SECRET_KEY) < 32:
                raise ValueError("PRODUCTION SECURITY FAILURE: Insecure or default SECRET_KEY detected! Set custom SECRET_KEY in environment.")
            if not self.ADMIN_API_KEY or self.ADMIN_API_KEY in insecure_defaults:
                raise ValueError("PRODUCTION SECURITY FAILURE: Insecure or default ADMIN_API_KEY detected! Set custom ADMIN_API_KEY in environment.")

settings = Settings()

