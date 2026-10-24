import re
import csv
import io
import uuid
import json
import logging
import datetime
from decimal import Decimal
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, WebSocket, WebSocketDisconnect, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, desc, delete
from passlib.hash import pbkdf2_sha256
from jose import jwt, JWTError

from database.models import get_db, Reseller, Customer, CreditLedger, License, SystemConfig, PackageRelease, AuditLog, utc_now, is_license_expired
from services.credit_service import (
    to_exact_credit,
    get_duration_pricing,
    FIXED_DURATION_PRICING,
    atomic_generate_reseller_key,
    reconcile_seller_credits,
    CREDIT_QUANTIZER
)
from services.realtime import realtime_hub
from config import settings

logger = logging.getLogger("auth_gateway.seller")

router = APIRouter(tags=["Seller Portal"])

NEPAL_TZ_OFFSET = datetime.timedelta(hours=5, minutes=45)

def format_nepal_time(dt: Optional[datetime.datetime], fmt: str = "%b %d, %Y") -> str:
    if not dt:
        return "—"
    return (dt + NEPAL_TZ_OFFSET).strftime(fmt)

# Reseller key extension credit cost pricing:
EXTENSION_CREDIT_PRICING: Dict[int, Decimal] = {
    1: Decimal("0.05"),
    3: Decimal("0.15"),
    7: Decimal("0.50"),
    15: Decimal("1.00"),
    30: Decimal("2.00"),
}

# Track revoked seller tokens
revoked_seller_tokens = set()

# -------------------------------------------------------------------------
# AUTHENTICATION & DEPENDENCIES
# -------------------------------------------------------------------------
def create_seller_jwt(reseller: Reseller) -> str:
    expire = utc_now() + datetime.timedelta(minutes=settings.SELLER_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(reseller.id),
        "seller_id": reseller.id,
        "username": reseller.username,
        "role": "seller",
        "exp": expire,
        "jti": str(uuid.uuid4())
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

async def get_current_seller(request: Request, db: AsyncSession = Depends(get_db)) -> Reseller:
    token = None
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    else:
        token = request.cookies.get(settings.SELLER_SESSION_COOKIE)

    if not token or token in revoked_seller_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: Valid seller session missing."
        )

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("role") != "seller":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Invalid account role."
            )
        seller_id = int(payload.get("seller_id") or payload.get("sub"))
    except (JWTError, ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid credentials."
        )

    res = await db.execute(select(Reseller).where(Reseller.id == seller_id))
    seller = res.scalars().first()
    if not seller:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Seller account not found.")

    if seller.status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Seller account has been {seller.status}. Contact administration."
        )

    return seller

async def get_seller_optional(request: Request, db: AsyncSession) -> Optional[Reseller]:
    try:
        return await get_current_seller(request, db)
    except HTTPException:
        return None

# -------------------------------------------------------------------------
# PURPLE EDITORIAL THEME FOR SELLER PORTAL
# -------------------------------------------------------------------------
SELLER_SHARED_CSS = """
:root {
    --bg-base: #06050a;
    --bg-surface: #0b0910;
    --bg-surface-elevated: #110e1a;
    --bg-surface-hover: #171322;
    --border: rgba(255, 255, 255, 0.08);
    --border-hover: rgba(255, 255, 255, 0.14);
    --primary: #a855f7;
    --primary-hover: #9333ea;
    --primary-active: #7e22ce;
    --primary-glow: rgba(168, 85, 247, 0.22);
    --text-primary: #ffffff;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --success: #10b981;
    --success-bg: rgba(16, 185, 129, 0.12);
    --success-border: rgba(16, 185, 129, 0.28);
    --danger: #ef4444;
    --danger-bg: rgba(239, 68, 68, 0.12);
    --danger-border: rgba(239, 68, 68, 0.28);
    --warning: #f59e0b;
    --warning-bg: rgba(245, 158, 11, 0.12);
    --warning-border: rgba(245, 158, 11, 0.28);
    --radius-sm: 8px;
    --radius-md: 12px;
    --radius-lg: 16px;
    --radius-pill: 9999px;
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background-color: var(--bg-base);
    color: var(--text-primary);
    font-family: var(--font-sans);
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    min-height: 100dvh;
    overflow-x: hidden;
    background-image: 
        radial-gradient(circle at 75% -5%, rgba(139, 92, 246, 0.06), transparent 45rem),
        linear-gradient(rgba(139, 92, 246, 0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(139, 92, 246, 0.04) 1px, transparent 1px);
    background-size: 100% 100%, 48px 48px, 48px 48px;
    background-attachment: fixed;
}
a { color: inherit; text-decoration: none; }
.app-shell { display: flex; min-height: 100vh; }
.sidebar {
    width: 260px;
    background: #08060c;
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    position: fixed;
    top: 0; bottom: 0; left: 0;
    z-index: 900;
}
.sidebar-header {
    padding: 24px 20px;
    display: flex;
    align-items: center;
    gap: 12px;
    border-bottom: 1px solid var(--border);
}
.logo-box {
    width: 36px; height: 36px;
    border-radius: var(--radius-sm);
    background: linear-gradient(135deg, #a855f7, #6366f1);
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; color: #fff; font-size: 17px;
    box-shadow: 0 0 16px rgba(168, 85, 247, 0.35);
    overflow: hidden;
}
.brand-info { display: flex; flex-direction: column; }
.brand-title { font-weight: 700; font-size: 15px; letter-spacing: -0.01em; color: #fff; }
.brand-sub { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; }
.sidebar-nav { padding: 18px 12px; display: flex; flex-direction: column; gap: 4px; }
.nav-section-title {
    font-size: 10px; font-weight: 700; color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 0.12em;
    padding: 8px 10px; margin-top: 8px;
}
.nav-item {
    display: flex; align-items: center; gap: 12px;
    padding: 10px 14px;
    border-radius: var(--radius-sm);
    font-size: 13.5px; font-weight: 500;
    color: var(--text-secondary);
    transition: all 0.18s ease;
    position: relative;
}
.nav-item:hover {
    color: #fff;
    background: var(--bg-surface-elevated);
}
.nav-item.active {
    color: #fff;
    background: rgba(168, 85, 247, 0.14);
    border: 1px solid rgba(168, 85, 247, 0.28);
    font-weight: 600;
}
.nav-dot {
    position: absolute; right: 12px;
    width: 6px; height: 6px; border-radius: 50%;
    background: var(--primary);
    box-shadow: 0 0 8px var(--primary);
}
.sidebar-footer {
    padding: 18px 16px;
    border-top: 1px solid var(--border);
    display: flex; flex-direction: column; gap: 12px;
}
.credit-pill-card {
    background: linear-gradient(135deg, rgba(168, 85, 247, 0.12), rgba(99, 102, 241, 0.08));
    border: 1px solid rgba(168, 85, 247, 0.24);
    border-radius: var(--radius-sm);
    padding: 10px 14px;
    display: flex; align-items: center; justify-content: space-between;
}
.credit-pill-label { font-size: 11px; color: var(--text-secondary); font-weight: 500; }
.credit-pill-val { font-size: 17px; font-weight: 700; color: #fff; letter-spacing: -0.01em; }
.user-card {
    display: flex; align-items: center; gap: 10px;
}
.user-avatar {
    width: 32px; height: 32px; border-radius: 50%;
    background: var(--bg-surface-elevated);
    border: 1px solid var(--border);
    color: var(--primary);
    display: flex; align-items: center; justify-content: center;
    font-weight: 600; font-size: 12px; position: relative;
}
.online-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--success);
    position: absolute; bottom: -1px; right: -1px;
    border: 2px solid #08060c;
}
.signout-link {
    display: flex; align-items: center; gap: 8px;
    font-size: 12.5px; color: var(--text-muted);
    transition: color 0.18s; padding: 4px 0;
}
.signout-link:hover { color: var(--danger); }
.main-wrapper {
    margin-left: 260px;
    flex: 1;
    min-width: 0;
    display: flex; flex-direction: column; min-height: 100vh;
}
.top-header {
    height: 64px;
    border-bottom: 1px solid var(--border);
    background: rgba(8, 6, 12, 0.85);
    backdrop-filter: blur(16px);
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 28px;
    position: sticky; top: 0; z-index: 800;
}
.header-left { display: flex; align-items: center; gap: 12px; }
.header-title { font-size: 16px; font-weight: 600; color: #fff; }
.header-right { display: flex; align-items: center; gap: 12px; }
.content-container {
    padding: 28px;
    max-width: 1360px;
    width: 100%;
}
.grid-4 {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
}
.panel {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    overflow: hidden;
}
.panel-header {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
}
.panel-title { font-size: 15px; font-weight: 600; color: #fff; }
.panel-body { padding: 20px; }
.table-responsive { width: 100%; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; text-align: left; }
thead th {
    background: #09070e;
    padding: 12px 16px;
    font-size: 11.5px; font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 0.05em;
    border-bottom: 1px solid var(--border);
}
tbody td {
    padding: 14px 16px;
    font-size: 13px;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
}
tbody tr:hover td { background: var(--bg-surface-elevated); color: #fff; }
.mono { font-family: var(--font-mono); }
.status-badge {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 3px 10px; border-radius: var(--radius-pill);
    font-size: 11px; font-weight: 500;
}
.status-success { background: var(--success-bg); color: var(--success); border: 1px solid var(--success-border); }
.status-warning { background: var(--warning-bg); color: var(--warning); border: 1px solid var(--warning-border); }
.status-danger { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger-border); }
.status-purple { background: rgba(168, 85, 247, 0.12); color: var(--primary); border: 1px solid rgba(168, 85, 247, 0.28); }
.status-violet { background: rgba(139, 92, 246, 0.12); color: #c4b5fd; border: 1px solid rgba(139, 92, 246, 0.25); }
.page-intro { margin-bottom: 24px; }
.page-intro-badge { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; color: var(--primary); margin-bottom: 8px; }
.page-intro-title { font-size: 24px; font-weight: 700; color: #ffffff; letter-spacing: -0.02em; margin-bottom: 6px; }
.page-intro-text { font-size: 13.5px; color: var(--text-secondary); max-width: 680px; line-height: 1.6; }
.btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 8px 16px; border-radius: var(--radius-sm);
    font-size: 13px; font-weight: 600;
    cursor: pointer; border: none; transition: all 0.18s ease; text-decoration: none;
}
.btn-primary {
    background: var(--primary); color: #fff;
    box-shadow: 0 0 14px var(--primary-glow);
}
.btn-primary:hover { background: var(--primary-hover); transform: translateY(-1px); }
.btn-secondary {
    background: var(--bg-surface-elevated); color: var(--text-primary);
    border: 1px solid var(--border);
}
.btn-secondary:hover { background: var(--bg-surface-hover); border-color: rgba(255, 255, 255, 0.16); }
.btn-ghost {
    background: transparent; color: var(--text-secondary); border: 1px solid transparent;
}
.btn-ghost:hover { color: #ffffff; background: rgba(255, 255, 255, 0.05); }
.btn-sm { padding: 5px 12px; font-size: 12px; }
.btn-danger, .btn-destructive {
    background: rgba(239, 68, 68, 0.15); color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
}
.btn-danger:hover, .btn-destructive:hover { background: #ef4444; color: #fff; }
.modal-backdrop {
    position: fixed !important; inset: 0 !important; width: 100vw !important; height: 100vh !important;
    background: rgba(3, 2, 5, 0.92) !important; backdrop-filter: blur(12px) !important;
    -webkit-backdrop-filter: blur(12px) !important; display: none !important;
    align-items: center !important; justify-content: center !important; z-index: 99999 !important; padding: 20px !important;
}
.modal-backdrop.open { display: flex !important; }
.input, .select {
    width: 100%;
    padding: 10px 14px;
    background: #09070e;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: #fff;
    font-size: 13.5px;
    outline: none;
    transition: border 0.18s ease;
}
.input:focus, .select:focus { border-color: var(--primary); box-shadow: 0 0 12px var(--primary-glow); }
.field-label { display: block; font-size: 12px; font-weight: 500; color: var(--text-secondary); margin-bottom: 6px; }
.modal-overlay {
    position: fixed; inset: 0; background: rgba(0, 0, 0, 0.8);
    backdrop-filter: blur(8px);
    display: none; align-items: center; justify-content: center;
    z-index: 10000; padding: 20px;
}
.modal-overlay.open { display: flex; }
.modal-card {
    background: #0c0a12;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    width: 100%; max-width: 480px;
    padding: 24px;
    box-shadow: 0 25px 60px rgba(0, 0, 0, 0.9), 0 0 30px rgba(168, 85, 247, 0.15);
    animation: modalPop 0.2s ease-out;
}
@keyframes modalPop {
    from { opacity: 0; transform: scale(0.96) translateY(8px); }
    to { opacity: 1; transform: scale(1) translateY(0); }
}
.modal-title { font-size: 18px; font-weight: 700; color: #fff; margin-bottom: 6px; }
.modal-desc { font-size: 13px; color: var(--text-secondary); line-height: 1.5; margin-bottom: 20px; }
.toast-container {
    position: fixed; bottom: 24px; right: 24px; z-index: 99999;
    display: flex; flex-direction: column; gap: 10px;
}
.toast {
    background: #110e1a;
    border: 1px solid var(--border);
    border-left: 4px solid var(--primary);
    padding: 12px 18px;
    border-radius: var(--radius-sm);
    box-shadow: 0 10px 30px rgba(0,0,0,0.8);
    font-size: 13px; color: #fff;
    display: flex; align-items: center; gap: 10px;
    animation: toastSlide 0.2s ease-out;
}
@keyframes toastSlide { from { transform: translateX(50px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
.dashboard-layout {
    display: grid;
    grid-template-columns: 1.45fr 0.85fr;
    gap: 20px;
    align-items: start;
}
.responsive-two-col, .profile-layout {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
}
.table-responsive {
    width: 100%;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    display: block;
}
.table-responsive table {
    min-width: 580px;
}

.activity-row {
    display: grid;
    grid-template-columns: 85px 145px 1fr;
    gap: 14px;
    align-items: center;
    padding: 13px 20px;
    border-bottom: 1px solid var(--border);
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

/* Mobile Drawer & Overlay Styles */
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
    border-color: rgba(255, 255, 255, 0.15);
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

/* Responsive Media Queries */
@media (max-width: 1024px) {
    .dashboard-layout {
        grid-template-columns: 1fr;
    }
    .grid-4 {
        grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
    }
    .responsive-two-col, .profile-layout {
        grid-template-columns: 1fr !important;
        gap: 20px !important;
    }
}
@media (max-width: 900px) {
    .sidebar {
        display: none !important;
    }
    .main-wrapper {
        margin-left: 0 !important;
        width: 100% !important;
        min-width: 0 !important;
    }
    .mobile-menu-btn {
        display: inline-flex !important;
    }
    .top-header {
        padding: 0 16px !important;
        height: 64px !important;
        gap: 12px !important;
    }
    .content-container {
        padding: 20px 16px !important;
    }
    .header-title {
        font-size: 16px !important;
    }
}
@media (max-width: 640px) {
    .grid-4 {
        grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
        gap: 10px !important;
    }
    .grid-4 > div {
        padding: 14px 14px !important;
        gap: 10px !important;
        border-radius: 12px !important;
    }
    .activity-row {
        grid-template-columns: 65px 110px 1fr !important;
        gap: 8px !important;
        padding: 10px 12px !important;
        font-size: 11.5px !important;
    }
    .page-intro-title {
        font-size: 20px !important;
    }
    .page-intro-text {
        font-size: 13px !important;
    }
    .panel-header {
        padding: 14px 16px !important;
    }
    .panel-body {
        padding: 16px !important;
    }
    .modal-card {
        padding: 18px !important;
        margin: 12px !important;
        max-width: calc(100vw - 24px) !important;
    }
}
@media (max-width: 440px) {
    .grid-4 {
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
    .header-right .status-badge span:last-child {
        display: none;
    }
}
"""

def render_seller_layout(title: str, seller: Reseller, content: str, active_tab: str = "dashboard") -> str:
    nav_items = [
        {"to": "/seller/dashboard", "label": "Dashboard", "key": "dashboard", "icon": """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>"""},
        {"to": "/seller/keys", "label": "License keys", "key": "keys", "icon": """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>"""},
        {"to": "/seller/credits", "label": "Credit Logs", "key": "credits", "icon": """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>"""},
        {"to": "/seller/profile", "label": "My profile", "key": "profile", "icon": """<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>"""},
    ]

    nav_links_html = ""
    for item in nav_items:
        is_active = (active_tab == item["key"])
        active_cls = "active" if is_active else ""
        dot = '<span class="nav-dot"></span>' if is_active else ""
        nav_links_html += f"""
        <a href="{item['to']}" class="nav-item {active_cls}">
            {item['icon']}
            <span>{item['label']}</span>
            {dot}
        </a>
        """

    balance_fmt = f"{to_exact_credit(seller.credit_balance):.2f}"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} • BYTE Force Reseller Portal</title>
    <style>{SELLER_SHARED_CSS}</style>
</head>
<body>
    <div class="app-shell">
        <aside class="sidebar">
            <div>
                <a href="/seller/dashboard" class="sidebar-header">
                    <div class="logo-box">
                        <img src="/admin/logo.jpg" alt="BYTE FORCE" style="width:100%;height:100%;object-fit:cover;border-radius:inherit;" onerror="this.style.display='none'; this.parentElement.innerText='BF';">
                    </div>
                    <div class="brand-info">
                        <span class="brand-title">BYTE FORCE</span>
                        <span class="brand-sub">Reseller Portal</span>
                    </div>
                </a>
                <div class="sidebar-nav">
                    <div class="nav-section-title">Navigation</div>
                    {nav_links_html}
                </div>
            </div>

            <div class="sidebar-footer">
                <div class="credit-pill-card">
                    <div>
                        <div class="credit-pill-label">Available credits</div>
                        <div id="liveBalanceVal" class="credit-pill-val">{balance_fmt}</div>
                    </div>
                    <button type="button" class="btn btn-primary" style="padding: 6px 10px; font-size: 11px;" onclick="openGenKeyModal()">+ Key</button>
                </div>
                <div class="user-card">
                    <div class="user-avatar">
                        {seller.username[:2].upper()}
                        <span class="online-dot"></span>
                    </div>
                    <div style="min-width:0; flex:1;">
                        <div style="font-size: 13px; font-weight: 600; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">@{seller.username}</div>
                        <div style="font-size: 11px; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{seller.email or 'Reseller Account'}</div>
                    </div>
                </div>
                <a href="/seller/logout" class="signout-link">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>
                    <span>Sign out</span>
                </a>
            </div>
        </aside>

        <!-- Mobile Drawer Overlay & Drawer -->
        <div id="mobileDrawerOverlay" class="mobile-drawer-overlay" onclick="closeMobileMenu()"></div>
        <div id="mobileDrawer" class="mobile-drawer">
            <div>
                <div class="mobile-drawer-header">
                    <a href="/seller/dashboard" class="sidebar-header" style="padding: 0; border: none; height: auto;">
                        <div class="logo-box">
                            <img src="/admin/logo.jpg" alt="BYTE FORCE" style="width:100%;height:100%;object-fit:cover;border-radius:inherit;" onerror="this.style.display='none'; this.parentElement.innerText='BF';">
                        </div>
                        <div class="brand-info">
                            <span class="brand-title">BYTE FORCE</span>
                            <span class="brand-sub">Reseller Portal</span>
                        </div>
                    </a>
                    <button type="button" class="mobile-drawer-close" onclick="closeMobileMenu()" aria-label="Close navigation menu">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                </div>
                <div class="sidebar-nav">
                    <div class="nav-section-title">Navigation</div>
                    {nav_links_html}
                </div>
            </div>

            <div class="sidebar-footer">
                <div class="credit-pill-card">
                    <div>
                        <div class="credit-pill-label">Available credits</div>
                        <div class="credit-pill-val">{balance_fmt}</div>
                    </div>
                    <button type="button" class="btn btn-primary" style="padding: 6px 10px; font-size: 11px;" onclick="closeMobileMenu(); openGenKeyModal();">+ Key</button>
                </div>
                <div class="user-card">
                    <div class="user-avatar">
                        {seller.username[:2].upper()}
                        <span class="online-dot"></span>
                    </div>
                    <div style="min-width:0; flex:1;">
                        <div style="font-size: 13px; font-weight: 600; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">@{seller.username}</div>
                        <div style="font-size: 11px; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{seller.email or 'Reseller Account'}</div>
                    </div>
                </div>
                <a href="/seller/logout" class="signout-link">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>
                    <span>Sign out</span>
                </a>
            </div>
        </div>

        <div class="main-wrapper">
            <header class="top-header">
                <div style="display: flex; align-items: center; gap: 12px; min-width: 0;">
                    <button type="button" class="mobile-menu-btn" onclick="openMobileMenu()" aria-label="Open navigation menu">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" x2="20" y1="12" y2="12"/><line x1="4" x2="20" y1="6" y2="6"/><line x1="4" x2="20" y1="18" y2="18"/></svg>
                    </button>
                    <div class="header-left">
                        <span style="font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em;">Portal</span>
                        <span style="color: var(--border);">/</span>
                        <h1 class="header-title">{title}</h1>
                    </div>
                </div>
                <div class="header-right">
                    <div class="status-badge status-success" style="font-size: 12px; padding: 5px 12px; display: inline-flex; align-items: center; gap: 6px;">
                        <span style="width: 6px; height: 6px; border-radius: 50%; background: currentColor;"></span>
                        <span>All systems nominal</span>
                    </div>
                </div>
            </header>

            <main class="content-container">
                {content}
            </main>
        </div>
    </div>

    <!-- Generic Key Generation Modal Available On All Pages -->
    <div id="genKeyModal" class="modal-overlay">
        <div class="modal-card">
            <h2 class="modal-title">Generate License Key</h2>
            <p class="modal-desc">Credits will be deducted automatically based on the server-enforced duration pricing.</p>

            <form id="genKeyForm" onsubmit="handleGenerateKey(event)">
                <div style="margin-bottom: 16px;">
                    <label class="field-label">License Duration</label>
                    <select id="genDuration" class="select" onchange="updatePricePreview()">
                        <option value="7" data-cost="0.5">7 Days (0.5 Credits)</option>
                        <option value="15" data-cost="1.0">15 Days (1.0 Credit)</option>
                        <option value="30" data-cost="2.0" selected>30 Days (2.0 Credits)</option>
                    </select>
                </div>

                <div style="margin-bottom: 16px;">
                    <label class="field-label">Key Prefix</label>
                    <input type="text" id="genKeyPrefix" class="input mono" value="BYTE" placeholder="e.g. Alex, VIP" style="text-transform: uppercase;">
                </div>

                <div style="margin-bottom: 20px;">
                    <label class="field-label">Customer Name or Tag (Optional)</label>
                    <input type="text" id="genCustName" class="input" placeholder="e.g. VIP Gamer, John Doe">
                </div>

                <div style="background: rgba(168, 85, 247, 0.08); border: 1px solid rgba(168, 85, 247, 0.22); border-radius: 8px; padding: 12px 14px; margin-bottom: 20px;">
                    <div style="display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 4px;">
                        <span style="color: var(--text-secondary);">Required Cost:</span>
                        <span id="previewCost" style="font-weight: 700; color: #fff;">2.00 Credits</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; font-size: 12px;">
                        <span style="color: var(--text-muted);">Current Balance:</span>
                        <span id="previewCurrentBal" style="color: var(--text-secondary);">{balance_fmt} Credits</span>
                    </div>
                </div>

                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button type="button" class="btn btn-secondary" onclick="closeGenKeyModal()">Cancel</button>
                    <button type="submit" id="genSubmitBtn" class="btn btn-primary">Confirm</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Key Success Display Modal -->
    <div id="keySuccessModal" class="modal-overlay">
        <div class="modal-card">
            <div style="width: 44px; height: 44px; border-radius: 50%; background: var(--success-bg); border: 1px solid var(--success-border); color: var(--success); display: flex; align-items: center; justify-content: center; margin-bottom: 14px;">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
            </div>
            <h2 class="modal-title">Key Generated Successfully!</h2>
            <p class="modal-desc">Copy this license key and deliver it to your customer.</p>
            <div style="background: #09070e; border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin-bottom: 20px; display: flex; align-items: center; justify-content: space-between;">
                <span id="createdKeyText" class="mono" style="font-size: 15px; font-weight: 600; color: var(--primary);">BYTE-XXXX-XXXX-XXXX</span>
                <button type="button" class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;" onclick="copyCreatedKey()">Copy</button>
            </div>
            <div style="display: flex; justify-content: flex-end;">
                <button type="button" class="btn btn-primary" onclick="closeKeySuccessModal()">Done</button>
            </div>
        </div>
    </div>

    <div id="toastContainer" class="toast-container"></div>

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

    function showToast(msg, isSuccess = true) {{
        const c = document.getElementById('toastContainer');
        const t = document.createElement('div');
        t.className = 'toast';
        t.style.borderLeftColor = isSuccess ? 'var(--success)' : 'var(--danger)';
        t.innerHTML = `<span>${{msg}}</span>`;
        c.appendChild(t);
        setTimeout(() => {{ t.remove(); }}, 4000);
    }}

    function openGenKeyModal() {{
        updatePricePreview();
        document.getElementById('genKeyModal').classList.add('open');
    }}
    function closeGenKeyModal() {{
        document.getElementById('genKeyModal').classList.remove('open');
    }}
    function closeKeySuccessModal() {{
        document.getElementById('keySuccessModal').classList.remove('open');
        window.location.reload();
    }}
    function copyCreatedKey() {{
        const text = document.getElementById('createdKeyText').innerText;
        navigator.clipboard.writeText(text);
        showToast("Key copied to clipboard!");
    }}

    function updatePricePreview() {{
        const sel = document.getElementById('genDuration');
        const opt = sel.options[sel.selectedIndex];
        const cost = opt.getAttribute('data-cost');
        document.getElementById('previewCost').innerText = `${{parseFloat(cost).toFixed(2)}} Credits`;
    }}

    async function handleGenerateKey(e) {{
        e.preventDefault();
        const btn = document.getElementById('genSubmitBtn');
        btn.disabled = true;
        btn.innerText = "Generating...";

        const duration = parseInt(document.getElementById('genDuration').value);
        const prefix = (document.getElementById('genKeyPrefix')?.value || 'BYTE').trim().toUpperCase();
        const name = document.getElementById('genCustName').value;
        const idempotencyKey = 'idem_' + Math.random().toString(36).substring(2) + Date.now();

        try {{
            const resp = await fetch('/api/v1/seller/keys/generate', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                    duration_days: duration,
                    prefix: prefix,
                    customer_name: name,
                    idempotency_key: idempotencyKey
                }})
            }});
            const data = await resp.json();
            if (!resp.ok) {{
                showToast(data.detail || "Key generation failed", false);
                btn.disabled = false;
                btn.innerText = "Confirm";
                return;
            }}
            closeGenKeyModal();
            document.getElementById('createdKeyText').innerText = data.key;
            document.getElementById('liveBalanceVal').innerText = parseFloat(data.balance_after).toFixed(2);
            document.getElementById('keySuccessModal').classList.add('open');
        }} catch (err) {{
            showToast("Network error: " + err.message, false);
            btn.disabled = false;
            btn.innerText = "Confirm";
        }}
    }}

    // Real-Time WebSocket with SSE Fallback
    (function initRealtime() {{
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${{protocol}}//${{location.host}}/ws/seller`;
        let ws;

        function connect() {{
            ws = new WebSocket(wsUrl);
            ws.onmessage = function(event) {{
                try {{
                    const msg = JSON.parse(event.data);
                    if (msg.type === 'BALANCE_UPDATED' || msg.type === 'KEY_GENERATED') {{
                        if (msg.data && msg.data.balance) {{
                            const el = document.getElementById('liveBalanceVal');
                            if (el) {{
                                el.innerText = parseFloat(msg.data.balance).toFixed(2);
                                el.style.color = 'var(--success)';
                                setTimeout(() => el.style.color = '#fff', 2000);
                            }}
                        }}
                        showToast(`Balance updated: ${{msg.data.balance}} credits (${{msg.data.event || msg.type}})`);
                    }} else if (msg.type === 'VERSION_UPDATED' || msg.type === 'SYSTEM_CONFIG_UPDATED') {{
                        if (msg.data && msg.data.version) {{
                            const vEl = document.getElementById('liveAppVersionVal');
                            if (vEl) {{
                                vEl.innerText = msg.data.version;
                                vEl.style.color = 'var(--primary)';
                                setTimeout(() => vEl.style.color = '#fff', 2000);
                            }}
                            showToast(`System version updated to ${{msg.data.version}}`);
                        }}
                    }}
                }} catch (e) {{}}
            }};
            ws.onclose = function() {{
                setTimeout(connect, 3000);
            }};
        }}
        connect();
    }})();
    </script>
</body>
</html>
"""

# -------------------------------------------------------------------------
# 1. SELLER AUTHENTICATION & LOGIN
# -------------------------------------------------------------------------
@router.get("/seller/login", response_class=HTMLResponse)
async def seller_login_page(request: Request, error: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    existing = await get_seller_optional(request, db)
    if existing:
        return RedirectResponse(url="/seller/dashboard", status_code=303)

    err_html = f'<div style="background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.28); color: #ef4444; padding: 12px 16px; border-radius: 8px; font-size: 13px; margin-bottom: 20px;">{error}</div>' if error else ''

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reseller Sign In • BYTE FORCE</title>
    <style>
        {SELLER_SHARED_CSS}
        .login-wrap {{
            min-height: 100vh;
            display: flex; align-items: center; justify-content: center;
            padding: 20px;
            background: radial-gradient(circle at 50% 20%, rgba(168, 85, 247, 0.12), transparent 40rem), var(--bg-base);
        }}
        .login-card {{
            width: 100%; max-width: 420px;
            background: #0b0910;
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 36px 32px;
            box-shadow: 0 25px 60px rgba(0, 0, 0, 0.9), 0 0 25px rgba(168, 85, 247, 0.12);
        }}
    </style>
</head>
<body>
    <div class="login-wrap">
        <div class="login-card">
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 24px;">
                <div class="logo-box">
                    <img src="/admin/logo.jpg" alt="BYTE FORCE" style="width:100%;height:100%;object-fit:cover;border-radius:inherit;" onerror="this.style.display='none'; this.parentElement.innerText='BF';">
                </div>
                <div>
                    <h2 style="font-size: 18px; font-weight: 700; color: #fff;">BYTE FORCE</h2>
                    <span style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.1em;">Reseller Portal</span>
                </div>
            </div>

            <h1 style="font-size: 22px; font-weight: 700; color: #fff; margin-bottom: 6px;">Welcome Back</h1>
            <p style="font-size: 13.5px; color: var(--text-secondary); margin-bottom: 24px;">Enter your reseller credentials to manage keys and customers.</p>

            {err_html}

            <form action="/seller/login" method="POST">
                <div style="margin-bottom: 18px;">
                    <label class="field-label">Reseller Username</label>
                    <input type="text" name="username" class="input" placeholder="Enter your username" required autocomplete="username">
                </div>

                <div style="margin-bottom: 24px;">
                    <label class="field-label">Account Password</label>
                    <input type="password" name="password" class="input" placeholder="Enter your password" required autocomplete="current-password">
                </div>

                <button type="submit" class="btn btn-primary" style="width: 100%; height: 44px; font-size: 14px;">
                    <span>Sign In to Dashboard</span>
                </button>
            </form>

            <div style="margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--border); text-align: center; font-size: 12px; color: var(--text-muted);">
                Authorized personnel only. Contact master admin to obtain reseller access.
            </div>
        </div>
    </div>
</body>
</html>"""
    return HTMLResponse(content=html)

@router.post("/seller/login")
async def seller_login_submit(request: Request, db: AsyncSession = Depends(get_db)):
    is_json = request.headers.get("content-type", "").startswith("application/json")
    if is_json:
        body = await request.json()
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
    else:
        form = await request.form()
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", ""))

    res = await db.execute(select(Reseller).where(Reseller.username == username))
    seller = res.scalars().first()

    is_valid = False
    if seller and seller.password_hash:
        try:
            is_valid = pbkdf2_sha256.verify(password, seller.password_hash)
        except Exception:
            is_valid = False

    if not is_valid:
        if is_json:
            raise HTTPException(status_code=401, detail="Invalid reseller username or password.")
        return RedirectResponse(url="/seller/login?error=Invalid+username+or+password", status_code=303)

    if seller.status != "active":
        msg = f"Your reseller account is {seller.status}. Contact administrator."
        if is_json:
            raise HTTPException(status_code=403, detail=msg)
        return RedirectResponse(url=f"/seller/login?error={msg.replace(' ', '+')}", status_code=303)

    seller.last_login_at = utc_now()
    await db.commit()

    token = create_seller_jwt(seller)

    if is_json:
        resp = JSONResponse({"success": True, "token": token, "seller": {"id": seller.id, "username": seller.username, "display_name": seller.display_name}})
    else:
        resp = RedirectResponse(url="/seller/dashboard", status_code=303)

    resp.set_cookie(
        key=settings.SELLER_SESSION_COOKIE,
        value=token,
        httponly=True,
        max_age=86400 * 7,
        samesite="lax",
        secure=settings.ADMIN_COOKIE_SECURE
    )
    return resp

@router.get("/seller/logout")
@router.post("/seller/logout")
async def seller_logout(request: Request):
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        revoked_seller_tokens.add(token)

    cookie_token = request.cookies.get(settings.SELLER_SESSION_COOKIE)
    if cookie_token:
        revoked_seller_tokens.add(cookie_token)

    if request.headers.get("accept") == "application/json":
        resp = JSONResponse({"success": True, "message": "Logged out."})
    else:
        resp = RedirectResponse(url="/seller/login", status_code=303)

    resp.delete_cookie(settings.SELLER_SESSION_COOKIE)
    return resp

# -------------------------------------------------------------------------
# 2. SELLER DASHBOARD VIEW
# -------------------------------------------------------------------------
@router.get("/seller/dashboard", response_class=HTMLResponse)
async def seller_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    seller = await get_seller_optional(request, db)
    if not seller:
        return RedirectResponse(url="/seller/login", status_code=303)

    # 1. License key distribution for this seller
    res_keys = await db.execute(select(License).where(License.seller_id == seller.id))
    all_seller_keys = res_keys.scalars().all()

    total_keys = len(all_seller_keys)
    expired_keys = sum(1 for k in all_seller_keys if is_license_expired(k) and k.status != "banned")
    active_keys = sum(1 for k in all_seller_keys if k.bound_device_hash is not None and not is_license_expired(k) and k.status != "banned")
    unused_keys = sum(1 for k in all_seller_keys if k.bound_device_hash is None and not is_license_expired(k) and k.status != "banned")
    banned_keys = sum(1 for k in all_seller_keys if k.status == "banned")

    unused_pct = round((unused_keys / total_keys * 100)) if total_keys > 0 else 0
    active_pct = round((active_keys / total_keys * 100)) if total_keys > 0 else 0
    expired_pct = round((expired_keys / total_keys * 100)) if total_keys > 0 else 0
    banned_pct = round((banned_keys / total_keys * 100)) if total_keys > 0 else 0

    # 2. Total customers assigned to this seller
    res_c = await db.execute(select(func.count(Customer.id)).where(Customer.seller_id == seller.id))
    total_customers = res_c.scalar() or 0

    # 3. System Config & Gateway Status
    cfg_res = await db.execute(select(SystemConfig).order_by(SystemConfig.id.desc()).limit(1))
    sys_cfg = cfg_res.scalars().first()
    app_status = (sys_cfg.app_status if sys_cfg else "ACTIVE").upper()
    is_active = (app_status == "ACTIVE")
    app_version = sys_cfg.app_version if (sys_cfg and sys_cfg.app_version) else "1.1.4"

    # 4. Recent activity logs for this seller (5 latest)
    res_act = await db.execute(
        select(CreditLedger).where(CreditLedger.seller_id == seller.id).order_by(CreditLedger.timestamp.desc()).limit(5)
    )
    recent_logs = res_act.scalars().all()

    recent_rows_html = ""
    for l in recent_logs:
        ttype = (l.transaction_type or "EVENT").upper()
        if "KEY" in ttype or l.related_key:
            badge_text = "add_key"
        elif "ALLOCATE" in ttype or "ADD" in ttype:
            badge_text = "add_credit"
        elif "DEDUCT" in ttype:
            badge_text = "deduct_credit"
        elif "REVERSAL" in ttype:
            badge_text = "reversal"
        else:
            badge_text = "add_key" if l.related_key else ttype.lower()

        raw_desc = l.description or ""
        desc_display = raw_desc

        if "KEY" in ttype or l.related_key or "Key generation" in raw_desc:
            m_days = re.search(r"\((\d+)\s*days?\)", raw_desc, re.IGNORECASE)
            duration_str = f"{m_days.group(1)}d" if m_days else ""

            key_str = l.related_key
            if not key_str:
                m_key = re.search(r"-\s*([A-Za-z0-9_\-]+)", raw_desc)
                if m_key:
                    key_str = m_key.group(1).strip()

            cost_val = abs(float(l.amount or 0))
            cost_str = f"{cost_val:.2f} credits" if cost_val > 0 else ""

            meta_parts = [p for p in [duration_str, cost_str] if p]
            meta_str = f" ({', '.join(meta_parts)})" if meta_parts else ""

            cust_str = ""
            if "for customer" in raw_desc:
                m_cust = re.search(r"for customer\s+([^\s\(\)]+)", raw_desc)
                if m_cust:
                    cust_str = f" for customer {m_cust.group(1)}"

            if key_str:
                desc_display = f"Added key: {key_str}{meta_str}{cust_str}"
            elif raw_desc.startswith("Key generation"):
                desc_display = raw_desc.replace("Key generation", "Added key", 1)

        time_str = format_nepal_time(l.timestamp, "%H:%M:%S")
        recent_rows_html += f"""
        <div class="activity-row">
            <span class="mono" style="color: var(--text-secondary); font-size: 12px; font-variant-numeric: tabular-nums;">{time_str}</span>
            <div>
                <span style="background: rgba(255, 255, 255, 0.07); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 9999px; padding: 4px 14px; font-size: 11.5px; font-weight: 600; color: #f1f5f9; display: inline-block; letter-spacing: 0.02em;">{badge_text}</span>
            </div>
            <span class="activity-details" title="{desc_display}" style="color: #94a3b8; font-size: 13px;">{desc_display}</span>
        </div>
        """

    if not recent_rows_html:
        recent_rows_html = '<div style="padding: 44px 20px; text-align: center; color: var(--text-muted); font-size: 13px;">No security events recorded yet.</div>'

    status_badge_html = '<span class="status-badge status-success" style="display:inline-flex; align-items:center; gap:6px;"><span style="width:6px; height:6px; border-radius:50%; background:currentColor;"></span>Active</span>' if is_active else '<span class="status-badge status-warning" style="display:inline-flex; align-items:center; gap:6px;"><span style="width:6px; height:6px; border-radius:50%; background:currentColor;"></span>Paused</span>'
    status_icon_color = "#10b981" if is_active else "#f59e0b"

    credit_val = float(seller.credit_balance or 0)
    if credit_val >= 1000:
        credit_display = f"{credit_val / 1000:.2f}K"
    else:
        credit_display = f"{credit_val:.2f}"

    seller_status_display = (seller.status or "active").lower()

    content = f"""
    <!-- Page Intro Header (Matching Admin) -->
    <div class="page-intro" style="margin-bottom: 28px;">
        <div class="page-intro-badge">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
            Secure administration
        </div>
        <h2 class="page-intro-title">Seller Dashboard</h2>
        <p class="page-intro-text">Manage and monitor your Reselling Business</p>
    </div>

    <!-- 4 Top Metrics (Modern Horizontal Cards) -->
    <div class="grid-4" style="gap: 16px; margin-bottom: 28px;">
        <!-- Card 1: Credit Balance -->
        <div style="background: #0d0c15; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 18px 20px; display: flex; align-items: center; gap: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);">
            <div style="width: 48px; height: 48px; min-width: 48px; border-radius: 14px; background: rgba(124, 58, 237, 0.12); border: 1px solid rgba(139, 92, 246, 0.22); display: flex; align-items: center; justify-content: center; color: #a78bfa;">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="5" rx="2"/><line x1="2" x2="22" y1="10" x2="10"/></svg>
            </div>
            <div style="display: flex; flex-direction: column; min-width: 0;">
                <div style="font-size: 13px; color: #94a3b8; font-weight: 500; line-height: 1.3; margin-bottom: 2px;">Credit Balance</div>
                <div style="font-size: 22px; font-weight: 700; color: #ffffff; line-height: 1.2; letter-spacing: -0.01em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{credit_display}</div>
            </div>
        </div>

        <!-- Card 2: Version -->
        <div style="background: #0d0c15; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 18px 20px; display: flex; align-items: center; gap: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);">
            <div style="width: 48px; height: 48px; min-width: 48px; border-radius: 14px; background: rgba(124, 58, 237, 0.12); border: 1px solid rgba(139, 92, 246, 0.22); display: flex; align-items: center; justify-content: center; color: #a78bfa;">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>
            </div>
            <div style="display: flex; flex-direction: column; min-width: 0;">
                <div style="font-size: 13px; color: #94a3b8; font-weight: 500; line-height: 1.3; margin-bottom: 2px;">Version</div>
                <div id="liveAppVersionVal" style="font-size: 22px; font-weight: 700; color: #ffffff; line-height: 1.2; letter-spacing: -0.01em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; transition: color 0.3s ease;">{app_version}</div>
            </div>
        </div>

        <!-- Card 3: Status -->
        <div style="background: #0d0c15; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 18px 20px; display: flex; align-items: center; gap: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);">
            <div style="width: 48px; height: 48px; min-width: 48px; border-radius: 14px; background: rgba(124, 58, 237, 0.12); border: 1px solid rgba(139, 92, 246, 0.22); display: flex; align-items: center; justify-content: center; color: #a78bfa;">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 20V10"/><path d="M12 20V4"/><path d="M6 20v-6"/></svg>
            </div>
            <div style="display: flex; flex-direction: column; min-width: 0;">
                <div style="font-size: 13px; color: #94a3b8; font-weight: 500; line-height: 1.3; margin-bottom: 2px;">Status</div>
                <div style="font-size: 22px; font-weight: 700; color: #ffffff; line-height: 1.2; letter-spacing: -0.01em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{seller_status_display}</div>
            </div>
        </div>

        <!-- Card 4: Users Added -->
        <div style="background: #0d0c15; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 18px 20px; display: flex; align-items: center; gap: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);">
            <div style="width: 48px; height: 48px; min-width: 48px; border-radius: 14px; background: rgba(124, 58, 237, 0.12); border: 1px solid rgba(139, 92, 246, 0.22); display: flex; align-items: center; justify-content: center; color: #a78bfa;">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
            </div>
            <div style="display: flex; flex-direction: column; min-width: 0;">
                <div style="font-size: 13px; color: #94a3b8; font-weight: 500; line-height: 1.3; margin-bottom: 2px;">Users Added</div>
                <div style="font-size: 22px; font-weight: 700; color: #ffffff; line-height: 1.2; letter-spacing: -0.01em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{total_customers}</div>
            </div>
        </div>
    </div>

    <!-- Two Column Layout (Matching Admin UI) -->
    <div class="dashboard-layout">
        <!-- Left: Recent Activity Feed -->
        <div class="panel" style="background: #0d0c15; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; overflow: hidden; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);">
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 18px 20px; border-bottom: 1px solid var(--border);">
                <div>
                    <h3 style="font-size: 15px; font-weight: 600; color: #ffffff;">Recent activity</h3>
                    <p style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">Latest authentication and key events</p>
                </div>
                <a href="/seller/credits" class="btn btn-ghost btn-sm" style="color: var(--text-secondary); display: inline-flex; align-items: center; gap: 6px;">
                    <span>View logs</span>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
                </a>
            </div>
            <div>
                {recent_rows_html}
            </div>
        </div>

        <!-- Right Column: App Status + Key Distribution -->
        <div style="display: flex; flex-direction: column; gap: 20px;">
            <!-- Application Status Card -->
            <div class="panel" style="background: #0d0c15; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 20px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);">
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
                <button type="button" class="btn btn-destructive" style="width: 100%; margin-top: 20px; height: 42px; font-weight: 600;" onclick="handleKillswitchNotice()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>
                    <span>Engage killswitch</span>
                </button>
            </div>

            <!-- Key Distribution Card -->
            <div class="panel" style="background: #0d0c15; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 20px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);">
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

    <!-- Killswitch Notice Modal -->
    <div id="killswitchNoticeModal" class="modal-backdrop">
        <div class="modal-card">
            <h3 class="modal-title">Administrative Privilege Required</h3>
            <p class="modal-desc">The global authentication killswitch is strictly managed by Root Administration. Reseller accounts cannot disengage gateway authorization.</p>
            <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
                <button type="button" class="btn btn-secondary" onclick="closeKillswitchModal()">Dismiss</button>
            </div>
        </div>
    </div>

    <script>
    function handleKillswitchNotice() {{
        const m = document.getElementById('killswitchNoticeModal');
        if (m) m.classList.add('open');
        else showToast('Root administrator authorization required to toggle gateway killswitch.', false);
    }}
    function closeKillswitchModal() {{
        const m = document.getElementById('killswitchNoticeModal');
        if (m) m.classList.remove('open');
    }}
    </script>
    """
    return HTMLResponse(content=render_seller_layout("Dashboard Overview", seller, content, active_tab="dashboard"))

# -------------------------------------------------------------------------
# 3. SELLER CUSTOMERS MANAGEMENT (/seller/users)
# -------------------------------------------------------------------------
@router.get("/seller/users", response_class=HTMLResponse)
async def seller_users_page(request: Request, db: AsyncSession = Depends(get_db)):
    seller = await get_seller_optional(request, db)
    if not seller:
        return RedirectResponse(url="/seller/login", status_code=303)

    res_cust = await db.execute(
        select(Customer).where(Customer.seller_id == seller.id).order_by(Customer.created_at.desc())
    )
    customers = res_cust.scalars().all()

    cust_rows_html = ""
    for c in customers:
        res_keys_count = await db.execute(
            select(func.count(License.id)).where(License.customer_id == c.id, License.seller_id == seller.id)
        )
        k_count = res_keys_count.scalar() or 0
        date_str = c.created_at.strftime("%b %d, %Y") if c.created_at else "—"

        cust_rows_html += f"""
        <tr>
            <td class="mono" style="color: var(--primary); font-weight: 600;">{c.customer_code}</td>
            <td style="font-weight: 600; color: #fff;">{c.name}</td>
            <td>{c.contact or '—'}</td>
            <td><span class="status-badge status-purple">{k_count} Key(s)</span></td>
            <td><span class="status-badge status-{ 'success' if c.status == 'active' else 'warning' }">{c.status.title()}</span></td>
            <td>{date_str}</td>
            <td>
                <button type="button" class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="generateKeyForCust({c.id}, '{c.name}')">+ Generate Key</button>
            </td>
        </tr>"""

    if not cust_rows_html:
        cust_rows_html = '<tr><td colspan="7" style="text-align:center; padding: 32px; color: var(--text-muted);">No customers created yet. Click "+ Add Customer" to register your first buyer.</td></tr>'

    content = f"""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <div>
            <h2 style="font-size: 20px; font-weight: 700; color: #fff;">Customer Directory</h2>
            <p style="font-size: 13px; color: var(--text-secondary);">Strictly isolated customer accounts assigned to your reseller profile.</p>
        </div>
        <button type="button" class="btn btn-primary" onclick="openAddCustModal()">+ Add Customer</button>
    </div>

    <div class="panel">
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Customer ID</th>
                        <th>Name / Identifier</th>
                        <th>Contact Handle</th>
                        <th>Licenses</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {cust_rows_html}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Add Customer Modal -->
    <div id="addCustModal" class="modal-overlay">
        <div class="modal-card">
            <h2 class="modal-title">Create Customer Profile</h2>
            <p class="modal-desc">Register a customer to group keys and track expiration dates.</p>
            <form onsubmit="handleAddCustomer(event)">
                <div style="margin-bottom: 16px;">
                    <label class="field-label">Customer Name / Identifier</label>
                    <input type="text" id="custNameInput" class="input" placeholder="e.g. Alex Gaming, User99" required>
                </div>
                <div style="margin-bottom: 16px;">
                    <label class="field-label">Contact (Discord / Telegram / Email)</label>
                    <input type="text" id="custContactInput" class="input" placeholder="@telegram_handle">
                </div>
                <div style="margin-bottom: 20px;">
                    <label class="field-label">Notes (Private)</label>
                    <input type="text" id="custNotesInput" class="input" placeholder="Optional notes for your reference">
                </div>
                <div style="display: flex; justify-content: flex-end; gap: 10px;">
                    <button type="button" class="btn btn-secondary" onclick="closeAddCustModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create Customer</button>
                </div>
            </form>
        </div>
    </div>

    <script>
    function openAddCustModal() {{ document.getElementById('addCustModal').classList.add('open'); }}
    function closeAddCustModal() {{ document.getElementById('addCustModal').classList.remove('open'); }}

    function generateKeyForCust(id, name) {{
        document.getElementById('genCustName').value = name;
        openGenKeyModal();
    }}

    async function handleAddCustomer(e) {{
        e.preventDefault();
        const name = document.getElementById('custNameInput').value;
        const contact = document.getElementById('custContactInput').value;
        const notes = document.getElementById('custNotesInput').value;

        const resp = await fetch('/api/v1/seller/customers', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ name, contact, notes }})
        }});
        if (resp.ok) {{
            window.location.reload();
        }} else {{
            const data = await resp.json();
            showToast(data.detail || "Failed to create customer", false);
        }}
    }}
    </script>
    """
    return HTMLResponse(content=render_seller_layout("Customer Management", seller, content, active_tab="users"))

# -------------------------------------------------------------------------
# 4. SELLER LICENSE KEYS (/seller/keys) - IDENTICAL TO ADMIN PORTAL
# -------------------------------------------------------------------------
@router.get("/seller/keys", response_class=HTMLResponse)
async def seller_keys_page(
    request: Request,
    filter: str = "All",
    q: Optional[str] = None,
    msg: Optional[str] = None,
    error: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    seller = await get_seller_optional(request, db)
    if not seller:
        return RedirectResponse(url="/seller/login", status_code=303)

    res_keys = await db.execute(
        select(License).where(License.seller_id == seller.id).order_by(License.created_at.desc())
    )
    all_keys = res_keys.scalars().all()

    current_filter = filter if filter in ["All", "Active", "Unused", "Expired", "Banned"] else "All"

    filtered = []
    total_expired_count = 0
    for k in all_keys:
        expired = is_license_expired(k)
        if expired and k.status != "banned":
            total_expired_count += 1

        if k.status == "banned":
            cat = "Banned"
        elif expired:
            cat = "Expired"
        elif k.bound_device_hash:
            cat = "Active"
        else:
            cat = "Unused"

        if current_filter != "All" and cat != current_filter:
            continue

        if q:
            q_clean = q.strip().lower()
            key_txt = (k.key or "").lower()
            hwid_txt = (k.bound_device_hash or "").lower()
            note_txt = (k.notes or "").lower()
            if q_clean not in key_txt and q_clean not in hwid_txt and q_clean not in note_txt:
                continue

        filtered.append(k)

    alert_html = ""
    if msg:
        alert_html += f'<div style="background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.28); color: #10b981; padding: 12px 18px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; font-weight: 500;">{msg}</div>'
    if error:
        alert_html += f'<div style="background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.28); color: #ef4444; padding: 12px 18px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; font-weight: 500;">{error}</div>'

    rows_html = ""
    for k in filtered:
        expired = is_license_expired(k)
        if k.status == "banned":
            status_badge = '<span class="status-badge status-danger"><span style="width:5px; height:5px; border-radius:50%; background:currentColor;"></span>Banned</span>'
        elif expired:
            status_badge = '<span class="status-badge status-warning" style="background: rgba(245, 158, 11, 0.12); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.28);"><span style="width:5px; height:5px; border-radius:50%; background:currentColor;"></span>Expired</span>'
        elif k.bound_device_hash:
            status_badge = '<span class="status-badge status-success"><span style="width:5px; height:5px; border-radius:50%; background:currentColor;"></span>Active</span>'
        else:
            status_badge = '<span class="status-badge status-violet"><span style="width:5px; height:5px; border-radius:50%; background:currentColor;"></span>Unused</span>'

        masked_key = k.key
        hwid_display = f"{k.bound_device_hash[:7]}…{k.bound_device_hash[-5:]}" if k.bound_device_hash else "Unbound"
        created_str = format_nepal_time(k.created_at, "%b %d, %Y") if k.created_at else "—"

        if k.status == "banned":
            exp_str = '<span style="color: var(--danger);">Banned</span>'
        elif expired:
            exp_time = format_nepal_time(k.expires_at, "%b %d, %Y") if k.expires_at else "Expired"
            exp_str = f'<span style="color: #f59e0b; font-weight: 500;">Expired ({exp_time})</span>'
        elif k.activated_at and k.expires_at:
            exp_str = f'<span>{format_nepal_time(k.expires_at, "%b %d, %Y")}</span>'
        elif getattr(k, "duration_days", None) and not k.activated_at:
            exp_str = f'<span style="color: #c4b5fd; font-weight: 500;">{k.duration_days} Days (Starts on use)</span>'
        else:
            exp_str = "Lifetime"

        notes_str = k.notes or "Reseller key"

        extend_btn = f"""
        <button type="button" class="btn btn-ghost" style="padding: 6px; color: #a78bfa;" title="Extend validity with credits" onclick="openExtendModal('{k.key}', '{masked_key}')">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        </button>
        """

        ban_unban_btn = f"""
        <form action="/seller/keys/unban" method="POST" style="display:inline;">
            <input type="hidden" name="key" value="{k.key}">
            <button type="submit" class="btn btn-ghost" style="padding: 6px;" title="Unban license">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>
            </button>
        </form>
        """ if k.status == "banned" else f"""
        <form action="/seller/keys/ban" method="POST" style="display:inline;">
            <input type="hidden" name="key" value="{k.key}">
            <button type="submit" class="btn btn-ghost" style="padding: 6px;" title="Ban license">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg>
            </button>
        </form>
        """

        reset_btn = f"""
        <button type="button" class="btn btn-ghost" style="padding: 6px;" title="Reset HWID lock" onclick="confirmAction({{ title: 'Reset HWID lock?', desc: 'Unbind hardware identifier for license key {k.key}. The user will be able to bind a new device on their next login.', action: '/seller/keys/reset-hwid', inputs: {{ key: '{k.key}' }}, confirmText: 'Reset HWID', variant: 'primary' }})">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
        </button>
        """ if k.bound_device_hash else f"""
        <button type="button" class="btn btn-ghost" style="padding: 6px; opacity: 0.3; cursor: not-allowed;" title="No hardware bound" disabled>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
        </button>
        """

        delete_btn = f"""
        <button type="button" class="btn btn-ghost" style="padding: 6px; color: var(--danger);" title="Delete license" onclick="confirmAction({{ title: 'Delete license key?', desc: 'Permanently delete key {k.key} from your inventory. This action cannot be undone.', action: '/seller/keys/delete', inputs: {{ key: '{k.key}' }}, confirmText: 'Delete key', variant: 'danger' }})">
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
            <td style="padding: 14px 16px;">
                <span class="mono" style="font-size: 12px; color: { '#ffffff' if k.bound_device_hash else 'var(--text-muted)' };">{hwid_display}</span>
            </td>
            <td style="padding: 14px 16px; font-size: 13px; color: var(--text-secondary);">{created_str}</td>
            <td style="padding: 14px 16px;">
                <div style="font-size: 13px;">{exp_str}</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 3px;">{notes_str}</div>
            </td>
            <td style="padding: 14px 20px; text-align: right;">
                <div style="display: inline-flex; align-items: center; gap: 2px;">
                    {extend_btn}
                    {ban_unban_btn}
                    {reset_btn}
                    {delete_btn}
                </div>
            </td>
        </tr>"""

    if not rows_html:
        rows_html = '<tr><td colspan="6" style="padding: 48px; text-align: center; color: var(--text-muted); font-size: 13px;">No license keys match this view.</td></tr>'

    filter_buttons_html = ""
    for f_opt in ["All", "Active", "Unused", "Expired", "Banned"]:
        btn_class = "btn-secondary" if current_filter == f_opt else "btn-ghost"
        badge = ""
        if f_opt == "Expired" and total_expired_count > 0:
            badge = f' <span style="background: rgba(245, 158, 11, 0.2); color: #f59e0b; padding: 1px 7px; border-radius: 10px; font-size: 11px; margin-left: 4px; font-weight: 600;">{total_expired_count}</span>'
        filter_buttons_html += f'<a href="/seller/keys?filter={f_opt}&q={q or ""}" class="btn {btn_class} btn-sm">{f_opt}{badge}</a>'

    all_table_keys_multiline = "\\n".join([k.key for k in filtered])

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
            <a href="/api/v1/seller/keys/export?filter={current_filter}&q={q or ''}" class="btn btn-secondary" title="Export visible keys as CSV file">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                <span>Export CSV</span>
            </a>
            <button type="button" class="btn btn-secondary" onclick="copyAllKeys('{all_table_keys_multiline}', this)" title="Copy all keys visible in current table">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
                <span>Copy listed ({len(filtered)})</span>
            </button>
            <button type="button" class="btn btn-primary" onclick="openGenKeyModal()">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                <span>Generate keys</span>
            </button>
        </div>
    </div>

    {alert_html}

    <!-- Filter & Search Toolbar -->
    <div class="panel" style="padding: 12px; margin-bottom: 16px; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px;">
        <form action="/seller/keys" method="GET" style="display: flex; align-items: center; gap: 8px; flex: 1; min-width: 200px;">
            <input type="hidden" name="filter" value="{current_filter}">
            <div style="position: relative; width: 100%; max-width: 400px; display: flex; align-items: center;">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" style="position: absolute; left: 14px; top: 50%; transform: translateY(-50%); pointer-events: none; z-index: 2;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <input type="text" name="q" class="input" style="padding-left: 42px !important; height: 38px; font-size: 13px; background: rgba(255, 255, 255, 0.03);" placeholder="Search by key or HWID" value="{q or ''}">
            </div>
        </form>
        <div style="display: flex; gap: 4px; overflow-x: auto; max-width: 100%; -webkit-overflow-scrolling: touch; padding-bottom: 2px;">
            {filter_buttons_html}
        </div>
    </div>

    <!-- Keys Table Panel -->
    <div class="panel" style="overflow-x: auto; -webkit-overflow-scrolling: touch;">
        <table style="width: 100%; min-width: 680px; border-collapse: collapse; text-align: left;">
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

    <!-- Extend / Renew Modal with Credits -->
    <div id="extendModal" class="modal-backdrop">
        <div class="modal-card" style="max-width: 440px; border-radius: var(--radius-md);">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
                <div>
                    <h3 class="modal-title" style="font-size: 19px; font-weight: 700; color: #fff;">Extend / Renew license</h3>
                    <p class="modal-desc" style="font-size: 13px; margin-top: 4px; color: var(--text-secondary);">Add validity days with credits. Deducted automatically from your balance.</p>
                </div>
                <button type="button" class="btn btn-ghost btn-sm" onclick="closeModal('extendModal')" style="padding: 4px 8px; color: var(--text-muted);" aria-label="Close modal">✕</button>
            </div>

            <form action="/seller/keys/extend" method="POST">
                <input type="hidden" name="key" id="extendKeyInput">

                <div style="margin-bottom: 14px;">
                    <label class="field-label">Target license</label>
                    <div id="extendKeyDisplay" class="mono" style="font-size: 13px; font-weight: 600; color: #c084fc; background: rgba(139, 92, 246, 0.1); border: 1px solid rgba(139, 92, 246, 0.25); padding: 9px 12px; border-radius: 6px; word-break: break-all;"></div>
                </div>

                <div style="margin-bottom: 14px; background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border); padding: 10px 14px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 12px; color: var(--text-muted);">Your balance:</span>
                    <span style="font-size: 14px; font-weight: 700; color: var(--success);">{seller.credit_balance:.2f} Credits</span>
                </div>

                <div style="margin-bottom: 20px;">
                    <label class="field-label">Extension Duration & Cost</label>
                    <select name="add_days" class="select" style="height: 42px; cursor: pointer;">
                        <option value="1">1 Day — 0.05 credits</option>
                        <option value="3">3 Days — 0.15 credits</option>
                        <option value="7" selected>7 Days (1 week) — 0.50 credits</option>
                        <option value="15">15 Days — 1.00 credit</option>
                        <option value="30">30 Days (1 month) — 2.00 credits</option>
                    </select>
                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">
                        If expired, validity extends from now. If unused, adds to initial validity days.
                    </div>
                </div>

                <div style="display: flex; justify-content: flex-end; gap: 10px; border-top: 1px solid var(--border); padding-top: 18px;">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('extendModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary" style="padding: 9px 20px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                        <span>Confirm & Extend</span>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Generic Confirm Action Modal -->
    <div id="appConfirmModal" class="modal-backdrop">
        <div class="modal-card" style="max-width: 440px; border-radius: var(--radius-md);">
            <div style="display: flex; align-items: flex-start; gap: 14px; margin-bottom: 18px;">
                <div id="appConfirmIconContainer" style="width: 40px; height: 40px; border-radius: 10px; display: grid; place-items: center; flex-shrink: 0; border: 1px solid var(--border);">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                </div>
                <div>
                    <h3 id="appConfirmTitle" class="modal-title" style="font-size: 17px; margin-bottom: 4px;">Confirm action</h3>
                    <p id="appConfirmDesc" class="modal-desc" style="font-size: 13px; line-height: 1.5; margin-bottom: 0;">Are you sure?</p>
                </div>
            </div>
            <form id="appConfirmForm" method="POST">
                <div id="appConfirmInputs"></div>
                <div style="display: flex; justify-content: flex-end; gap: 10px; border-top: 1px solid var(--border); padding-top: 16px;">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('appConfirmModal')">Cancel</button>
                    <button type="submit" id="appConfirmSubmitBtn" class="btn btn-primary">Confirm</button>
                </div>
            </form>
        </div>
    </div>

    <div id="copyToast" style="position: fixed; bottom: 24px; right: 24px; z-index: 100000; background: #14101d; border: 1px solid var(--border); padding: 10px 18px; border-radius: 8px; font-size: 13px; font-weight: 500; display: none; box-shadow: 0 10px 30px rgba(0,0,0,0.8); align-items: center; gap: 8px; color: #ffffff;">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
        <span id="copyToastText">License key copied to clipboard</span>
    </div>

    <script>
    function closeModal(id) {{
        const el = document.getElementById(id);
        if (el) el.classList.remove('open');
    }}
    function openModal(id) {{
        const el = document.getElementById(id);
        if (el) el.classList.add('open');
    }}

    function openExtendModal(rawKey, maskedKey) {{
        const input = document.getElementById('extendKeyInput');
        const display = document.getElementById('extendKeyDisplay');
        if (input) input.value = rawKey;
        if (display) display.innerText = maskedKey || rawKey;
        openModal('extendModal');
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
            for (const [name, val] of Object.entries(options.inputs)) {{
                const hiddenInput = document.createElement('input');
                hiddenInput.type = 'hidden';
                hiddenInput.name = name;
                hiddenInput.value = val;
                inputsContainer.appendChild(hiddenInput);
            }}
        }}

        openModal('appConfirmModal');
        return false;
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
            btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>';
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
    return HTMLResponse(content=render_seller_layout("License keys", seller, content, active_tab="keys"))

# -------------------------------------------------------------------------
# 4.1. SELLER LICENSE ACTIONS: EXTEND, RESET HWID, BAN, UNBAN, DELETE
# -------------------------------------------------------------------------
@router.post("/seller/keys/extend")
async def seller_extend_key_submit(
    request: Request,
    key: str = Form(...),
    add_days: int = Form(7),
    db: AsyncSession = Depends(get_db)
):
    seller = await get_seller_optional(request, db)
    if not seller:
        return RedirectResponse(url="/seller/login", status_code=303)

    if add_days not in EXTENSION_CREDIT_PRICING:
        return RedirectResponse(url=f"/seller/keys?error=Invalid+extension+duration+{add_days}+days.", status_code=303)

    cost = EXTENSION_CREDIT_PRICING[add_days]

    result = await db.execute(select(License).where(License.key == key, License.seller_id == seller.id))
    lic = result.scalars().first()
    if not lic:
        return RedirectResponse(url="/seller/keys?error=License+key+not+found+or+not+owned+by+your+account.", status_code=303)

    if seller.credit_balance < cost:
        return RedirectResponse(
            url=f"/seller/keys?error=Insufficient+credits.+Required:+{cost:.2f}+credits+(Your+balance:+{seller.credit_balance:.2f}).",
            status_code=303
        )

    balance_before = seller.credit_balance
    balance_after = balance_before - cost
    seller.credit_balance = balance_after

    ledger = CreditLedger(
        transaction_id=f"tx_ext_{uuid.uuid4().hex[:12]}",
        seller_id=seller.id,
        transaction_type="KEY_EXTEND",
        amount=-cost,
        balance_before=balance_before,
        balance_after=balance_after,
        description=f"Key extension ({add_days} days) - {lic.key}",
        related_key=lic.key,
        initiated_by=seller.username,
        timestamp=utc_now(),
        status="COMPLETED"
    )
    db.add(ledger)

    now = utc_now()
    if is_license_expired(lic):
        lic.expires_at = now + datetime.timedelta(days=add_days)
        lic.status = "active"
        msg = f"License+{key}+renewed+for+{add_days}+days+({cost:.2f}+credits+debited)."
    elif lic.activated_at is None:
        current_dur = lic.duration_days or 0
        lic.duration_days = current_dur + add_days
        msg = f"License+{key}+initial+duration+extended+by+{add_days}+days+({cost:.2f}+credits+debited)."
    else:
        base_time = lic.expires_at if lic.expires_at and lic.expires_at > now else now
        lic.expires_at = base_time + datetime.timedelta(days=add_days)
        lic.status = "active"
        msg = f"License+{key}+validity+extended+by+{add_days}+days+({cost:.2f}+credits+debited)."

    db.add(AuditLog(
        action="SELLER_KEY_EXTEND",
        details=f"Seller '{seller.username}' extended key '{lic.key}' by {add_days} days for {cost:.2f} credits. New balance: {balance_after:.2f}."
    ))

    await db.commit()
    try:
        await realtime_hub.broadcast_credit_update(seller.id, float(balance_after))
    except Exception:
        pass

    return RedirectResponse(url=f"/seller/keys?msg={msg}", status_code=303)

@router.post("/seller/keys/reset-hwid")
async def seller_reset_hwid_submit(
    request: Request,
    key: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    seller = await get_seller_optional(request, db)
    if not seller:
        return RedirectResponse(url="/seller/login", status_code=303)

    result = await db.execute(select(License).where(License.key == key, License.seller_id == seller.id))
    lic = result.scalars().first()
    if not lic:
        return RedirectResponse(url="/seller/keys?error=License+key+not+found+or+not+owned+by+your+account.", status_code=303)

    old_hash = lic.bound_device_hash
    lic.bound_device_hash = None
    if lic.status != "banned" and not is_license_expired(lic):
        lic.status = "active"

    db.add(AuditLog(
        action="SELLER_RESET_HWID",
        details=f"Seller '{seller.username}' reset HWID binding for key '{lic.key}'."
    ))
    await db.commit()
    return RedirectResponse(url=f"/seller/keys?msg=Device+binding+reset+successfully.", status_code=303)

@router.post("/seller/keys/ban")
async def seller_ban_key_submit(
    request: Request,
    key: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    seller = await get_seller_optional(request, db)
    if not seller:
        return RedirectResponse(url="/seller/login", status_code=303)

    result = await db.execute(select(License).where(License.key == key, License.seller_id == seller.id))
    lic = result.scalars().first()
    if not lic:
        return RedirectResponse(url="/seller/keys?error=License+key+not+found.", status_code=303)

    lic.status = "banned"
    db.add(AuditLog(
        action="SELLER_KEY_BAN",
        details=f"Seller '{seller.username}' banned key '{lic.key}'."
    ))
    await db.commit()
    return RedirectResponse(url="/seller/keys?msg=License+key+banned+successfully.", status_code=303)

@router.post("/seller/keys/unban")
async def seller_unban_key_submit(
    request: Request,
    key: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    seller = await get_seller_optional(request, db)
    if not seller:
        return RedirectResponse(url="/seller/login", status_code=303)

    result = await db.execute(select(License).where(License.key == key, License.seller_id == seller.id))
    lic = result.scalars().first()
    if not lic:
        return RedirectResponse(url="/seller/keys?error=License+key+not+found.", status_code=303)

    lic.status = "expired" if is_license_expired(lic) else "active"
    db.add(AuditLog(
        action="SELLER_KEY_UNBAN",
        details=f"Seller '{seller.username}' unbanned key '{lic.key}'."
    ))
    await db.commit()
    return RedirectResponse(url="/seller/keys?msg=License+key+unbanned+successfully.", status_code=303)

@router.post("/seller/keys/delete")
async def seller_delete_key_submit(
    request: Request,
    key: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    seller = await get_seller_optional(request, db)
    if not seller:
        return RedirectResponse(url="/seller/login", status_code=303)

    result = await db.execute(select(License).where(License.key == key, License.seller_id == seller.id))
    lic = result.scalars().first()
    if not lic:
        return RedirectResponse(url="/seller/keys?error=License+key+not+found.", status_code=303)

    await db.delete(lic)
    db.add(AuditLog(
        action="SELLER_KEY_DELETE",
        details=f"Seller '{seller.username}' deleted key '{key}' from inventory."
    ))
    await db.commit()
    return RedirectResponse(url="/seller/keys?msg=License+key+deleted.", status_code=303)

# -------------------------------------------------------------------------
# 5. SELLER APP RELEASES (/seller/versions) - READ ONLY
# -------------------------------------------------------------------------
@router.get("/seller/versions", response_class=HTMLResponse)
async def seller_versions_page(request: Request, db: AsyncSession = Depends(get_db)):
    seller = await get_seller_optional(request, db)
    if not seller:
        return RedirectResponse(url="/seller/login", status_code=303)

    res_cfg = await db.execute(select(SystemConfig).order_by(SystemConfig.id.desc()).limit(1))
    cfg = res_cfg.scalars().first()

    res_pkg = await db.execute(select(PackageRelease).order_by(PackageRelease.published_at.desc()))
    releases = res_pkg.scalars().all()

    rel_cards_html = ""
    for r in releases:
        size_kb = round(r.file_size / 1024, 1) if r.file_size else 0
        pub_date = r.published_at.strftime("%b %d, %Y · %H:%M") if r.published_at else "—"
        rel_cards_html += f"""
        <div class="panel" style="margin-bottom: 16px;">
            <div class="panel-header">
                <div>
                    <span style="font-weight: 700; color: #fff; font-size: 15px;">{r.package_name}</span>
                    <span class="status-badge status-purple" style="margin-left: 8px;">{r.version_tag}</span>
                </div>
                <span class="mono" style="font-size: 11px; color: var(--text-muted);">{pub_date}</span>
            </div>
            <div class="panel-body">
                <div style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 14px;">
                    {r.release_notes or 'No changelog description provided.'}
                </div>
                <div style="display: flex; gap: 20px; font-size: 12px; color: var(--text-muted); border-top: 1px solid var(--border); padding-top: 12px;">
                    <span>Filename: <strong class="mono" style="color: #fff;">{r.filename}</strong></span>
                    <span>Size: <strong style="color: #fff;">{size_kb} KB</strong></span>
                    <span>SHA-256: <strong class="mono" style="color: #fff;">{r.file_sha256[:12]}...</strong></span>
                </div>
            </div>
        </div>"""

    if not rel_cards_html:
        rel_cards_html = '<div class="panel" style="padding: 32px; text-align: center; color: var(--text-muted);">No official package releases published yet by administrator.</div>'

    current_ver = cfg.app_version if cfg else "1.1.4"
    download_link = cfg.download_url if cfg and cfg.download_url else "#"
    notes = cfg.release_notes if cfg else "Official Release"

    content = f"""
    <div style="margin-bottom: 24px;">
        <h2 style="font-size: 20px; font-weight: 700; color: #fff;">Supported Application Releases</h2>
        <p style="font-size: 13px; color: var(--text-secondary);">Official builds and security packages published by the master administrator for your customers.</p>
    </div>

    <!-- Active Master Release Info -->
    <div class="panel" style="margin-bottom: 24px; border-color: rgba(168, 85, 247, 0.3);">
        <div class="panel-header" style="background: rgba(168, 85, 247, 0.08);">
            <div>
                <span style="font-weight: 700; color: #fff;">Current Production Gateway Version: v{current_ver}</span>
                <span class="status-badge status-success" style="margin-left: 8px;">Published</span>
            </div>
            <a href="{download_link}" target="_blank" class="btn btn-primary" style="font-size: 12px; padding: 6px 14px;">Download Official IPA</a>
        </div>
        <div class="panel-body">
            <div style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.6;">
                {notes}
            </div>
        </div>
    </div>

    <div style="font-size: 14px; font-weight: 600; color: #fff; margin-bottom: 12px;">Cloud Injected Modules & Patches</div>
    {rel_cards_html}
    """
    return HTMLResponse(content=render_seller_layout("Application Versions", seller, content, active_tab="versions"))

# -------------------------------------------------------------------------
# 6. SELLER CREDIT LOGS (/seller/credits, /seller/credit-logs, /seller/audit-logs)
# -------------------------------------------------------------------------
@router.get("/seller/credits", response_class=HTMLResponse)
@router.get("/seller/credit-logs", response_class=HTMLResponse)
@router.get("/seller/audit-logs", response_class=HTMLResponse)
async def seller_audit_logs_page(request: Request, db: AsyncSession = Depends(get_db)):
    seller = await get_seller_optional(request, db)
    if not seller:
        return RedirectResponse(url="/seller/login", status_code=303)

    res_ledger = await db.execute(
        select(CreditLedger).where(CreditLedger.seller_id == seller.id).order_by(CreditLedger.timestamp.desc())
    )
    entries = res_ledger.scalars().all()

    total_logs = len(entries)

    rows_html = ""
    for e in entries:
        time_str = format_nepal_time(e.timestamp, "%d/%m/%Y, %H:%M:%S") if e.timestamp else "—"
        ttype = (e.transaction_type or "EVENT").upper()

        if "KEY" in ttype or e.related_key:
            badge_text = "add_key"
        elif "ALLOCATE" in ttype or "ADD" in ttype:
            badge_text = "add_credit"
        elif "DEDUCT" in ttype:
            badge_text = "deduct_credit"
        elif "REVERSAL" in ttype:
            badge_text = "reversal"
        else:
            badge_text = "add_key" if e.related_key else ttype.lower()

        amt = float(e.amount or 0)
        if amt < 0:
            credit_str = f"{amt:.2f}"
            credit_color = "#ef4444"
        elif amt > 0:
            credit_str = f"+{amt:.2f}"
            credit_color = "#10b981"
        else:
            credit_str = "0.00"
            credit_color = "#94a3b8"

        raw_desc = e.description or ""
        desc_display = raw_desc

        if "KEY" in ttype or e.related_key or "Key generation" in raw_desc:
            m_days = re.search(r"\((\d+)\s*days?\)", raw_desc, re.IGNORECASE)
            duration_str = f"{m_days.group(1)}d" if m_days else ""

            key_str = e.related_key
            if not key_str:
                m_key = re.search(r"-\s*([A-Za-z0-9_\-]+)", raw_desc)
                if m_key:
                    key_str = m_key.group(1).strip()

            cost_val = abs(amt)
            cost_str = f"{cost_val:.2f} credits" if cost_val > 0 else ""

            meta_parts = [p for p in [duration_str, cost_str] if p]
            meta_str = f" ({', '.join(meta_parts)})" if meta_parts else ""

            cust_str = ""
            if "for customer" in raw_desc:
                m_cust = re.search(r"for customer\s+([^\s\(\)]+)", raw_desc)
                if m_cust:
                    cust_str = f" for customer {m_cust.group(1)}"

            if key_str:
                desc_display = f"Added key: {key_str}{meta_str}{cust_str}"
            elif raw_desc.startswith("Key generation"):
                desc_display = raw_desc.replace("Key generation", "Added key", 1)

        search_corpus = f"{e.transaction_id} {badge_text} {time_str} {credit_str} {desc_display} {raw_desc} {e.related_key or ''}".lower()

        rows_html += f"""
        <tr class="audit-row" data-search="{search_corpus}" style="border-bottom: 1px solid rgba(255, 255, 255, 0.05); transition: background 0.15s;">
            <td style="padding: 16px; font-size: 13.5px; color: #cbd5e1; white-space: nowrap; font-variant-numeric: tabular-nums;">{time_str}</td>
            <td style="padding: 16px;">
                <span style="background: rgba(255, 255, 255, 0.07); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 9999px; padding: 4px 14px; font-size: 11.5px; font-weight: 600; color: #f1f5f9; display: inline-block; letter-spacing: 0.02em;">{badge_text}</span>
            </td>
            <td style="padding: 16px;">
                <span style="color: {credit_color}; font-weight: 600; font-size: 14px; font-variant-numeric: tabular-nums;">{credit_str}</span>
            </td>
            <td style="padding: 16px; font-size: 13.5px; color: #94a3b8; line-height: 1.4;">{desc_display}</td>
        </tr>"""

    if not rows_html:
        rows_html = '<tr><td colspan="4" style="text-align:center; padding: 48px; color: var(--text-muted); font-size: 13px;">No credit transactions recorded yet.</td></tr>'

    content = f"""
    <!-- Page Header (Matching Reference Design) -->
    <div style="margin-bottom: 24px;">
        <h2 style="font-size: 22px; font-weight: 700; color: #fff; letter-spacing: -0.01em;">Credit History</h2>
    </div>

    <!-- Transaction History Card -->
    <div style="background: #0d0c15; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 24px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 22px; gap: 14px; flex-wrap: wrap;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>
                    <path d="M3 3v5h5"/>
                    <path d="M12 7v5l4 2"/>
                </svg>
                <h3 style="font-size: 18px; font-weight: 700; color: #ffffff; margin: 0; letter-spacing: -0.01em;">Transaction History</h3>
            </div>
            <div style="display: flex; align-items: center; gap: 10px; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; padding: 7px 12px; flex: 1; min-width: 200px; max-width: 380px;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--text-muted); flex-shrink: 0;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <input type="text" id="auditSearchInput" placeholder="Filter transaction history..." oninput="filterAuditLogs()" style="background: transparent; border: none; outline: none; color: #fff; font-size: 13px; width: 100%;">
            </div>
        </div>

        <div class="table-responsive">
            <table style="width: 100%; min-width: 580px; border-collapse: collapse;">
                <thead>
                    <tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08);">
                        <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 500; color: #64748b; width: 220px;">Date</th>
                        <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 500; color: #64748b; width: 140px;">Type</th>
                        <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 500; color: #64748b; width: 130px;">Credits</th>
                        <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 500; color: #64748b;">Description</th>
                    </tr>
                </thead>
                <tbody id="auditLogsBody">
                    {rows_html}
                </tbody>
            </table>
        </div>
    </div>

    <script>
    function filterAuditLogs() {{
        const q = (document.getElementById('auditSearchInput').value || '').toLowerCase().trim();
        const rows = document.querySelectorAll('.audit-row');
        rows.forEach(r => {{
            const text = r.getAttribute('data-search') || '';
            if (!q || text.includes(q)) {{
                r.style.display = '';
            }} else {{
                r.style.display = 'none';
            }}
        }});
    }}
    </script>
    """
    return HTMLResponse(content=render_seller_layout("Credit Logs", seller, content, active_tab="credits"))

# -------------------------------------------------------------------------
# 7. SELLER PROFILE (/seller/profile)
# -------------------------------------------------------------------------
@router.get("/seller/profile", response_class=HTMLResponse)
async def seller_profile_page(request: Request, db: AsyncSession = Depends(get_db)):
    seller = await get_seller_optional(request, db)
    if not seller:
        return RedirectResponse(url="/seller/login", status_code=303)

    created_str = seller.created_at.strftime("%B %d, %Y") if seller.created_at else "—"
    login_str = format_nepal_time(seller.last_login_at, "%B %d, %Y · %H:%M NPT") if seller.last_login_at else "First active session"

    content = f"""
    <div style="margin-bottom: 24px;">
        <h2 style="font-size: 20px; font-weight: 700; color: #fff;">Reseller Account Profile</h2>
        <p style="font-size: 13px; color: var(--text-secondary);">Review your credentials, authorized permissions, and update your password.</p>
    </div>

    <div class="profile-layout" style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">
        <!-- Profile Overview Card -->
        <div class="panel">
            <div class="panel-header">
                <span class="panel-title">Account Information</span>
                <span class="status-badge status-success">{seller.status.title()}</span>
            </div>
            <div class="panel-body">
                <div style="display: flex; flex-direction: column; gap: 16px;">
                    <div>
                        <div class="field-label">Reseller Username</div>
                        <div class="mono" style="font-size: 15px; font-weight: 600; color: #fff;">@{seller.username}</div>
                    </div>
                    <div>
                        <div class="field-label">Account Identifier</div>
                        <div class="mono" style="font-size: 13px; color: var(--text-secondary);">SELLER-UID-{seller.id}</div>
                    </div>
                    <div>
                        <div class="field-label">Registered Email</div>
                        <div style="font-size: 14px; color: #fff;">{seller.email or 'Not provided'}</div>
                    </div>
                    <div>
                        <div class="field-label">Registration Date</div>
                        <div style="font-size: 13px; color: var(--text-secondary);">{created_str}</div>
                    </div>
                    <div>
                        <div class="field-label">Last Successful Authentication</div>
                        <div style="font-size: 13px; color: var(--text-secondary);">{login_str}</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Change Password Card -->
        <div class="panel">
            <div class="panel-header">
                <span class="panel-title">Change Account Password</span>
            </div>
            <div class="panel-body">
                <form id="changePassForm" onsubmit="handleChangePassword(event)">
                    <div style="margin-bottom: 16px;">
                        <label class="field-label">Current Password</label>
                        <input type="password" id="currPassInput" class="input" required>
                    </div>
                    <div style="margin-bottom: 16px;">
                        <label class="field-label">New Password</label>
                        <input type="password" id="newPassInput" class="input" required minlength="6">
                    </div>
                    <div style="margin-bottom: 24px;">
                        <label class="field-label">Confirm New Password</label>
                        <input type="password" id="confirmPassInput" class="input" required minlength="6">
                    </div>
                    <button type="submit" id="passBtn" class="btn btn-primary" style="width: 100%;">Update Password</button>
                </form>
            </div>
        </div>
    </div>

    <script>
    async function handleChangePassword(e) {{
        e.preventDefault();
        const cur = document.getElementById('currPassInput').value;
        const n1 = document.getElementById('newPassInput').value;
        const n2 = document.getElementById('confirmPassInput').value;

        if (n1 !== n2) {{
            showToast("New passwords do not match!", false);
            return;
        }}

        const btn = document.getElementById('passBtn');
        btn.disabled = true;
        btn.innerText = "Updating...";

        try {{
            const resp = await fetch('/api/v1/seller/change-password', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ current_password: cur, new_password: n1 }})
            }});
            const data = await resp.json();
            if (resp.ok) {{
                showToast("Password updated successfully!");
                document.getElementById('changePassForm').reset();
            }} else {{
                showToast(data.detail || "Password change failed", false);
            }}
        }} catch (err) {{
            showToast("Network error: " + err.message, false);
        }} finally {{
            btn.disabled = false;
            btn.innerText = "Update Password";
        }}
    }}
    </script>
    """
    return HTMLResponse(content=render_seller_layout("My Profile", seller, content, active_tab="profile"))

# -------------------------------------------------------------------------
# 8. REST APIS FOR SELLER PORTAL
# -------------------------------------------------------------------------
class SellerKeyGenRequest(BaseModel):
    duration_days: int = Field(..., description="Duration in days: 7, 15, or 30")
    customer_id: Optional[int] = None
    customer_name: Optional[str] = None
    customer_contact: Optional[str] = None
    prefix: str = "BYTE"
    notes: Optional[str] = None
    idempotency_key: Optional[str] = None

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6)

class AddCustomerRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    contact: Optional[str] = None
    notes: Optional[str] = None

@router.post("/api/v1/seller/keys/generate")
async def api_seller_generate_key(
    req: SellerKeyGenRequest,
    request: Request,
    seller: Reseller = Depends(get_current_seller),
    db: AsyncSession = Depends(get_db)
):
    client_ip = request.client.host if request.client else "unknown"
    return await atomic_generate_reseller_key(
        db=db,
        seller_id=seller.id,
        duration_days=req.duration_days,
        customer_id=req.customer_id,
        new_customer_name=req.customer_name,
        new_customer_contact=req.customer_contact,
        prefix=req.prefix,
        notes=req.notes,
        idempotency_key=req.idempotency_key,
        client_ip=client_ip
    )

@router.get("/api/v1/seller/keys/export")
@router.get("/seller/keys/export")
async def export_seller_keys_csv(
    filter: str = "All",
    q: Optional[str] = None,
    seller: Reseller = Depends(get_current_seller),
    db: AsyncSession = Depends(get_db)
):
    res = await db.execute(select(License).where(License.seller_id == seller.id).order_by(License.created_at.desc()))
    keys = res.scalars().all()

    current_filter = filter if filter in ["All", "Active", "Unused", "Expired", "Banned"] else "All"
    filtered = []
    for k in keys:
        expired = is_license_expired(k)
        if k.status == "banned":
            cat = "Banned"
        elif expired:
            cat = "Expired"
        elif k.bound_device_hash:
            cat = "Active"
        else:
            cat = "Unused"

        if current_filter != "All" and cat != current_filter:
            continue

        if q:
            q_clean = q.strip().lower()
            key_txt = (k.key or "").lower()
            hwid_txt = (k.bound_device_hash or "").lower()
            note_txt = (k.notes or "").lower()
            if q_clean not in key_txt and q_clean not in hwid_txt and q_clean not in note_txt:
                continue

        filtered.append(k)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["License Key", "Duration Days", "Status", "Bound Device HWID", "Created At", "Expires At", "Notes"])

    for k in filtered:
        writer.writerow([
            k.key,
            k.duration_days or "Lifetime",
            k.status,
            k.bound_device_hash or "Unbound",
            k.created_at.isoformat() if k.created_at else "",
            k.expires_at.isoformat() if k.expires_at else "",
            k.notes or ""
        ])

    output.seek(0)
    filename = f"byte_force_keys_seller_{seller.username}_{datetime.date.today()}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.post("/api/v1/seller/customers")
async def api_add_customer(
    req: AddCustomerRequest,
    seller: Reseller = Depends(get_current_seller),
    db: AsyncSession = Depends(get_db)
):
    cust_code = f"CUST-{uuid.uuid4().hex[:8].upper()}"
    cust = Customer(
        seller_id=seller.id,
        customer_code=cust_code,
        name=req.name.strip(),
        contact=(req.contact or "").strip() if req.contact else None,
        notes=(req.notes or "").strip() if req.notes else None,
        status="active",
        created_at=utc_now()
    )
    db.add(cust)
    await db.commit()
    await db.refresh(cust)
    return {
        "success": True,
        "customer": {
            "id": cust.id,
            "code": cust.customer_code,
            "name": cust.name,
            "contact": cust.contact,
            "status": cust.status
        }
    }

@router.post("/api/v1/seller/change-password")
async def api_seller_change_password(
    req: ChangePasswordRequest,
    seller: Reseller = Depends(get_current_seller),
    db: AsyncSession = Depends(get_db)
):
    if not pbkdf2_sha256.verify(req.current_password, seller.password_hash):
        raise HTTPException(status_code=400, detail="Current password verification failed.")

    seller.password_hash = pbkdf2_sha256.hash(req.new_password)
    await db.commit()
    return {"success": True, "message": "Password changed successfully."}

# -------------------------------------------------------------------------
# 9. REAL-TIME WEBSOCKET FOR SELLER
# -------------------------------------------------------------------------
@router.websocket("/ws/seller")
async def websocket_seller_endpoint(websocket: WebSocket, db: AsyncSession = Depends(get_db)):
    # Authenticate token from cookie or query param
    token = websocket.query_params.get("token") or websocket.cookies.get(settings.SELLER_SESSION_COOKIE)
    if not token or token in revoked_seller_tokens:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("role") != "seller":
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        seller_id = int(payload.get("seller_id") or payload.get("sub"))
    except Exception:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await realtime_hub.connect_seller_ws(seller_id, websocket)
    try:
        while True:
            # Keepalive / ping handling
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await realtime_hub.disconnect_seller_ws(seller_id, websocket)
    except Exception:
        await realtime_hub.disconnect_seller_ws(seller_id, websocket)
