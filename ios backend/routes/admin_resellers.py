import re
import csv
import io
import uuid
import json
import logging
import datetime
from decimal import Decimal
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, desc
from passlib.hash import pbkdf2_sha256
from jose import jwt, JWTError

from database.models import (
    get_db, Reseller, Customer, CreditLedger, License,
    SystemConfig, AuditLog, utc_now, is_license_expired
)
from services.credit_service import (
    to_exact_credit,
    allocate_credits,
    deduct_credits,
    reconcile_seller_credits,
    reconcile_all_resellers,
    FIXED_DURATION_PRICING
)
from services.realtime import realtime_hub
from config import settings

logger = logging.getLogger("auth_gateway.admin_resellers")

NEPAL_TZ_OFFSET = datetime.timedelta(hours=5, minutes=45)

def format_nepal_time(dt: Optional[datetime.datetime], fmt: str = "%b %d, %H:%M") -> str:
    if not dt:
        return "Never"
    return (dt + NEPAL_TZ_OFFSET).strftime(fmt)

router = APIRouter(tags=["Admin Reseller & Credit Management"])

# -------------------------------------------------------------------------
# ADMIN AUTHENTICATION VERIFICATION
# -------------------------------------------------------------------------
def require_admin(request: Request):
    """
    Strict server-side verification: Only authenticated Super Admins can access.
    Sellers attempting to access will be denied.
    """
    from routes.admin import verify_admin_session
    try:
        if verify_admin_session(request):
            return True
    except HTTPException:
        pass
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Administrator authentication required."
    )

def check_admin_html(request: Request) -> bool:
    from routes.admin import verify_admin_session
    try:
        return verify_admin_session(request)
    except Exception:
        return False

# -------------------------------------------------------------------------
# ADMIN PURPLE EDITORIAL LAYOUT RENDERER
# -------------------------------------------------------------------------
def render_admin_shell(title: str, content: str, active_tab: str = "resellers", eyebrow: str = "Access") -> str:
    from main import render_layout
    return render_layout(title=title, eyebrow=eyebrow, content=content, active_tab=active_tab)


# -------------------------------------------------------------------------
# 1. ADMIN RESELLERS LIST VIEW (/admin/resellers)
# -------------------------------------------------------------------------
@router.get("/admin/resellers", response_class=HTMLResponse)
async def admin_resellers_page(request: Request, db: AsyncSession = Depends(get_db)):
    if not check_admin_html(request):
        return RedirectResponse(url="/admin/login", status_code=303)

    res = await db.execute(select(Reseller).order_by(Reseller.created_at.desc()))
    resellers = res.scalars().all()

    rows_html = ""
    for r in resellers:
        res_keys = await db.execute(select(func.count(License.id)).where(License.seller_id == r.id))
        key_count = res_keys.scalar() or 0

        status_tone = "success" if r.status == "active" else "danger"
        last_seen = format_nepal_time(r.last_login_at, "%b %d, %H:%M") if r.last_login_at else "Never"

        email_val = r.email if r.email else '<span style="color:var(--text-muted);">&mdash;</span>'
        rows_html += f"""
        <tr>
            <td class="mono" style="padding: 14px 20px; border-bottom: 1px solid var(--border); font-weight: 700; color: var(--primary);">#{r.id}</td>
            <td class="mono" style="padding: 14px 20px; border-bottom: 1px solid var(--border); font-weight: 600; color: #fff;">@{r.username}</td>
            <td style="padding: 14px 20px; border-bottom: 1px solid var(--border); font-size: 13px; color: var(--text-secondary);">{email_val}</td>
            <td style="padding: 14px 20px; border-bottom: 1px solid var(--border); font-size: 14px; font-weight: 700; color: #fff;">{r.credit_balance:.2f}</td>
            <td style="padding: 14px 20px; border-bottom: 1px solid var(--border);"><span class="status-badge status-purple">{key_count} keys</span></td>
            <td style="padding: 14px 20px; border-bottom: 1px solid var(--border);"><span class="status-badge status-{status_tone}">{r.status.title()}</span></td>
            <td style="padding: 14px 20px; border-bottom: 1px solid var(--border); font-size: 12px; color: var(--text-muted);">{last_seen}</td>
            <td style="padding: 14px 20px; border-bottom: 1px solid var(--border); text-align: right;">
                <div style="display: flex; justify-content: flex-end; gap: 4px; align-items: center;">
                    <button type="button" class="btn btn-ghost" style="padding: 6px; color: #10b981;" title="Allocate credits" onclick="openAllocModal({r.id}, '{r.username}')">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
                    </button>
                    <button type="button" class="btn btn-ghost" style="padding: 6px; color: #f59e0b;" title="Deduct credits" onclick="openDeductModal({r.id}, '{r.username}')">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
                    </button>
                    <a href="/admin/resellers/{r.id}" class="btn btn-ghost" style="padding: 6px; color: #a78bfa;" title="Inspect reseller details">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
                    </a>
                </div>
            </td>
        </tr>"""

    if not rows_html:
        rows_html = '<tr><td colspan="8" style="padding: 48px; text-align: center; color: var(--text-muted); font-size: 13px;">No resellers enrolled yet. Click "+ Create Reseller" to approve your first reseller.</td></tr>'

    content = f"""
    <div style="display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 20px; margin-bottom: 24px;">
        <div class="page-intro" style="margin-bottom: 0;">
            <div class="page-intro-badge">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                Secure administration
            </div>
            <h2 class="page-intro-title">Reseller accounts</h2>
            <p class="page-intro-text">Manage authorized sellers, allocate prepaid credits, inspect activity, and adjust permissions.</p>
        </div>
        <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
            <button type="button" class="btn btn-primary" onclick="openCreateResellerModal()">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                <span>Create Reseller</span>
            </button>
        </div>
    </div>

    <!-- Resellers Table Panel -->
    <div class="panel" style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; text-align: left;">
            <thead style="background: rgba(255, 255, 255, 0.02); border-bottom: 1px solid var(--border); font-size: 10px; text-transform: uppercase; letter-spacing: 0.12em; color: var(--text-muted);">
                <tr>
                    <th style="padding: 14px 20px; font-weight: 600;">ID</th>
                    <th style="padding: 14px 20px; font-weight: 600;">Username</th>
                    <th style="padding: 14px 20px; font-weight: 600;">Email</th>
                    <th style="padding: 14px 20px; font-weight: 600;">Available Credits</th>
                    <th style="padding: 14px 20px; font-weight: 600;">Issued Keys</th>
                    <th style="padding: 14px 20px; font-weight: 600;">Status</th>
                    <th style="padding: 14px 20px; font-weight: 600;">Last Login</th>
                    <th style="padding: 14px 20px; font-weight: 600; text-align: right;">Actions</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>

    <!-- Create Reseller Modal -->
    <div id="createResellerModal" class="modal-backdrop">
        <div class="modal-card">
            <h2 class="modal-title">Enrol New Reseller</h2>
            <p class="modal-desc">Create a dedicated reseller portal account with distinct permissions and optional initial credits.</p>
            <form onsubmit="handleCreateReseller(event)">
                <div style="margin-bottom: 14px;">
                    <label class="field-label">Username</label>
                    <input type="text" id="newUsername" class="input" placeholder="e.g. Alex" required autocomplete="off">
                </div>
                <div style="margin-bottom: 14px;">
                    <label class="field-label">Password</label>
                    <input type="password" id="newPassword" class="input" placeholder="Strong initial password" required minlength="6">
                </div>
                <div style="margin-bottom: 14px;">
                    <label class="field-label">Email (Optional)</label>
                    <input type="email" id="newEmail" class="input" placeholder="reseller@example.com">
                </div>
                <div style="margin-bottom: 20px;">
                    <label class="field-label">Initial Credits (Optional)</label>
                    <input type="number" step="0.5" id="newInitialCredits" class="input" value="0.0">
                </div>
                <div style="display: flex; justify-content: flex-end; gap: 10px;">
                    <button type="button" class="btn btn-secondary" onclick="closeCreateResellerModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create Reseller</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Allocate Credits Modal -->
    <div id="allocModal" class="modal-backdrop">
        <div class="modal-card">
            <h2 class="modal-title">Allocate Credits</h2>
            <p class="modal-desc">Add credits to the reseller's balance. This will be recorded in the immutable ledger.</p>
            <form onsubmit="handleAllocSubmit(event)">
                <input type="hidden" id="allocSellerId">
                <div style="margin-bottom: 14px;">
                    <label class="field-label">Target Reseller</label>
                    <input type="text" id="allocTargetName" class="input" readonly style="opacity: 0.7;">
                </div>
                <div style="margin-bottom: 14px;">
                    <label class="field-label">Credit Amount to Add</label>
                    <input type="number" step="0.5" id="allocAmount" class="input" placeholder="e.g. 50.0" required min="0.5">
                </div>
                <div style="margin-bottom: 20px;">
                    <label class="field-label">Reason / Reference</label>
                    <input type="text" id="allocReason" class="input" placeholder="e.g. Paid via USDT invoice #892" required>
                </div>
                <div style="display: flex; justify-content: flex-end; gap: 10px;">
                    <button type="button" class="btn btn-secondary" onclick="closeAllocModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Confirm Allocation</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Deduct Credits Modal -->
    <div id="deductModal" class="modal-backdrop">
        <div class="modal-card">
            <h2 class="modal-title">Deduct Credits</h2>
            <p class="modal-desc">Administrative reduction of credits. Mandatory reason required.</p>
            <form onsubmit="handleDeductSubmit(event)">
                <input type="hidden" id="deductSellerId">
                <div style="margin-bottom: 14px;">
                    <label class="field-label">Target Reseller</label>
                    <input type="text" id="deductTargetName" class="input" readonly style="opacity: 0.7;">
                </div>
                <div style="margin-bottom: 14px;">
                    <label class="field-label">Credit Amount to Deduct</label>
                    <input type="number" step="0.5" id="deductAmount" class="input" placeholder="e.g. 10.0" required min="0.5">
                </div>
                <div style="margin-bottom: 20px;">
                    <label class="field-label">Mandatory Reason</label>
                    <input type="text" id="deductReason" class="input" placeholder="e.g. Chargeback adjustment / refund" required>
                </div>
                <div style="display: flex; justify-content: flex-end; gap: 10px;">
                    <button type="button" class="btn btn-secondary" onclick="closeDeductModal()">Cancel</button>
                    <button type="submit" class="btn btn-destructive">Confirm Deduction</button>
                </div>
            </form>
        </div>
    </div>

    <script>
    function openCreateResellerModal() {{ openModal('createResellerModal'); }}
    function closeCreateResellerModal() {{ closeModal('createResellerModal'); }}

    function openAllocModal(id, username) {{
        document.getElementById('allocSellerId').value = id;
        document.getElementById('allocTargetName').value = '@' + username;
        openModal('allocModal');
    }}
    function closeAllocModal() {{ closeModal('allocModal'); }}

    function openDeductModal(id, username) {{
        document.getElementById('deductSellerId').value = id;
        document.getElementById('deductTargetName').value = '@' + username;
        openModal('deductModal');
    }}
    function closeDeductModal() {{ closeModal('deductModal'); }}

    async function handleCreateReseller(e) {{
        e.preventDefault();
        const username = document.getElementById('newUsername').value;
        const password = document.getElementById('newPassword').value;
        const email = document.getElementById('newEmail').value;
        const initial_credits = parseFloat(document.getElementById('newInitialCredits').value || "0");

        const resp = await fetch('/api/v1/admin/resellers', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ username, password, email, initial_credits }})
        }});
        if (resp.ok) {{
            window.location.reload();
        }} else {{
            const data = await resp.json();
            alert(data.detail || "Error creating reseller");
        }}
    }}

    async function handleAllocSubmit(e) {{
        e.preventDefault();
        const id = document.getElementById('allocSellerId').value;
        const amount = parseFloat(document.getElementById('allocAmount').value);
        const reason = document.getElementById('allocReason').value;

        const resp = await fetch(`/api/v1/admin/resellers/${{id}}/allocate-credits`, {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ amount, reason }})
        }});
        if (resp.ok) {{
            window.location.reload();
        }} else {{
            const data = await resp.json();
            alert(data.detail || "Error allocating credits");
        }}
    }}

    async function handleDeductSubmit(e) {{
        e.preventDefault();
        const id = document.getElementById('deductSellerId').value;
        const amount = parseFloat(document.getElementById('deductAmount').value);
        const reason = document.getElementById('deductReason').value;

        const resp = await fetch(`/api/v1/admin/resellers/${{id}}/deduct-credits`, {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ amount, reason }})
        }});
        if (resp.ok) {{
            window.location.reload();
        }} else {{
            const data = await resp.json();
            alert(data.detail || "Error deducting credits");
        }}
    }}
    </script>
    """
    return HTMLResponse(content=render_admin_shell("Resellers", content, active_tab="resellers", eyebrow="Access"))

# -------------------------------------------------------------------------
# 2. ADMIN RESELLER DETAIL VIEW (/admin/resellers/{seller_id})
# -------------------------------------------------------------------------
@router.get("/admin/resellers/{seller_id}", response_class=HTMLResponse)
async def admin_reseller_detail_page(seller_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    if not check_admin_html(request):
        return RedirectResponse(url="/admin/login", status_code=303)

    res = await db.execute(select(Reseller).where(Reseller.id == seller_id))
    seller = res.scalars().first()
    if not seller:
        raise HTTPException(status_code=404, detail="Reseller not found.")

    # Ledger entries for this seller
    res_l = await db.execute(
        select(CreditLedger).where(CreditLedger.seller_id == seller.id).order_by(CreditLedger.timestamp.desc()).limit(20)
    )
    ledger_entries = res_l.scalars().all()

    # Keys for this seller
    res_k = await db.execute(
        select(License).where(License.seller_id == seller.id).order_by(License.created_at.desc()).limit(20)
    )
    seller_keys = res_k.scalars().all()

    rec = await reconcile_seller_credits(db, seller.id)

    ledger_rows_html = ""
    for l in ledger_entries:
        is_pos = (l.amount > 0)
        amt_str = f"+{l.amount:.2f}" if is_pos else f"{l.amount:.2f}"
        tone = "success" if is_pos else "purple"
        ledger_rows_html += f"""
        <tr>
            <td class="mono" style="font-size: 11px;">{l.transaction_id}</td>
            <td><span class="status-badge status-{tone}">{l.transaction_type}</span></td>
            <td style="font-weight: 700; color: { 'var(--success)' if is_pos else '#fff' };">{amt_str}</td>
            <td>{l.balance_after:.2f}</td>
            <td>{l.description}</td>
            <td style="font-size: 11px; color: var(--text-muted);">{format_nepal_time(l.timestamp, '%Y-%m-%d %H:%M')}</td>
        </tr>"""

    if not ledger_rows_html:
        ledger_rows_html = '<tr><td colspan="6" style="text-align:center; padding: 20px; color: var(--text-muted);">No credit transactions for this reseller.</td></tr>'

    keys_rows_html = ""
    for k in seller_keys:
        status_tone = "success" if k.status == "active" and not is_license_expired(k) else "danger"
        keys_rows_html += f"""
        <tr>
            <td class="mono" style="color: var(--primary); font-weight: 600;">{k.key}</td>
            <td>{k.duration_days or 'Lifetime'} Days</td>
            <td><span class="status-badge status-{status_tone}">{k.status}</span></td>
            <td class="mono" style="font-size: 11px;">{k.bound_device_hash[:16] + '...' if k.bound_device_hash else 'Unbound'}</td>
            <td>{format_nepal_time(k.created_at, '%Y-%m-%d %H:%M') if k.created_at else '—'}</td>
        </tr>"""

    if not keys_rows_html:
        keys_rows_html = '<tr><td colspan="5" style="text-align:center; padding: 20px; color: var(--text-muted);">No keys generated yet.</td></tr>'

    content = f"""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <div>
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 4px;"><a href="/admin/resellers">&larr; Back to Resellers</a></div>
            <h2 style="font-size: 22px; font-weight: 700; color: #fff;">@{seller.username}</h2>
        </div>
        <div style="display: flex; gap: 10px;">
            <button type="button" class="btn { 'btn-destructive' if seller.status == 'active' else 'btn-primary' }" onclick="toggleSellerStatus({seller.id}, '{seller.status}')">
                { 'Suspend Account' if seller.status == 'active' else 'Activate Account' }
            </button>
        </div>
    </div>

    <!-- Metrics Header -->
    <div class="grid-4">
        <div class="panel" style="padding: 20px;">
            <div style="font-size: 12px; color: var(--text-muted); font-weight: 600;">CURRENT BALANCE</div>
            <div style="font-size: 32px; font-weight: 700; color: #fff; margin-top: 6px;">{seller.credit_balance:.2f}</div>
        </div>
        <div class="panel" style="padding: 20px;">
            <div style="font-size: 12px; color: var(--text-muted); font-weight: 600;">LEDGER INVARIANT</div>
            <div style="font-size: 20px; font-weight: 700; color: { 'var(--success)' if rec['is_reconciled'] else 'var(--danger)' }; margin-top: 14px;">
                { 'Reconciled (Match)' if rec['is_reconciled'] else 'Mismatch: ' + rec['discrepancy'] }
            </div>
        </div>
        <div class="panel" style="padding: 20px;">
            <div style="font-size: 12px; color: var(--text-muted); font-weight: 600;">KEYS ISSUED</div>
            <div style="font-size: 32px; font-weight: 700; color: var(--primary); margin-top: 6px;">{rec['total_issued_keys']}</div>
        </div>
        <div class="panel" style="padding: 20px;">
            <div style="font-size: 12px; color: var(--text-muted); font-weight: 600;">ACCOUNT STATUS</div>
            <div style="font-size: 24px; font-weight: 700; color: { 'var(--success)' if seller.status == 'active' else 'var(--danger)' }; margin-top: 12px;">{seller.status.upper()}</div>
        </div>
    </div>

    <!-- 2 Column Details: Keys and Ledger -->
    <div class="responsive-two-col" style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">
        <div class="panel">
            <div class="panel-header">
                <span class="panel-title">Keys Issued by Reseller</span>
            </div>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Key</th>
                            <th>Duration</th>
                            <th>Status</th>
                            <th>Bound HWID</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        {keys_rows_html}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="panel">
            <div class="panel-header">
                <span class="panel-title">Credit Ledger Journal</span>
            </div>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Tx ID</th>
                            <th>Type</th>
                            <th>Amount</th>
                            <th>Balance</th>
                            <th>Reason</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        {ledger_rows_html}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
    async function toggleSellerStatus(id, cur) {{
        const newStatus = (cur === 'active') ? 'suspended' : 'active';
        if (!confirm(`Are you sure you want to change reseller status to ${{newStatus}}?`)) return;

        const resp = await fetch(`/api/v1/admin/resellers/${{id}}/status`, {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ status: newStatus }})
        }});
        if (resp.ok) {{
            window.location.reload();
        }} else {{
            const data = await resp.json();
            alert(data.detail || "Error updating status");
        }}
    }}
    </script>
    """
    return HTMLResponse(content=render_admin_shell(f"Reseller #{seller.id} - {seller.username}", content, active_tab="resellers"))

# -------------------------------------------------------------------------
# 3. GLOBAL PLATFORM CREDIT LEDGER VIEW (/admin/credits)
# -------------------------------------------------------------------------
@router.get("/admin/credits", response_class=HTMLResponse)
async def admin_credits_page(request: Request, db: AsyncSession = Depends(get_db)):
    if not check_admin_html(request):
        return RedirectResponse(url="/admin/login", status_code=303)

    rec = await reconcile_all_resellers(db)

    # Top recent credit ledger entries platform-wide
    res_l = await db.execute(
        select(CreditLedger).order_by(CreditLedger.timestamp.desc()).limit(50)
    )
    entries = res_l.scalars().all()

    rows_html = ""
    for e in entries:
        is_pos = (e.amount > 0)
        amt_str = f"+{e.amount:.2f}" if is_pos else f"{e.amount:.2f}"
        tone = "success" if is_pos else "purple"
        time_str = format_nepal_time(e.timestamp, "%Y-%m-%d %H:%M:%S") if e.timestamp else "—"

        rows_html += f"""
        <tr>
            <td class="mono" style="font-size: 11px;">{e.transaction_id}</td>
            <td class="mono" style="color: var(--primary);">Reseller #{e.seller_id}</td>
            <td><span class="status-badge status-{tone}">{e.transaction_type}</span></td>
            <td style="font-weight: 700; color: { 'var(--success)' if is_pos else '#fff' };">{amt_str}</td>
            <td style="font-weight: 600;">{e.balance_after:.2f}</td>
            <td>{e.description}</td>
            <td style="font-size: 12px; color: var(--text-muted);">{e.initiated_by}</td>
            <td style="font-size: 11px; color: var(--text-muted);">{time_str}</td>
        </tr>"""

    if not rows_html:
        rows_html = '<tr><td colspan="8" style="text-align:center; padding: 32px; color: var(--text-muted);">No credit transactions recorded platform-wide.</td></tr>'

    content = f"""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <div>
            <h2 style="font-size: 20px; font-weight: 700; color: #fff;">Platform Credit Pool & Accounting</h2>
            <p style="font-size: 13px; color: var(--text-secondary);">Centralized ledger of all issued, consumed, and circulating credits across all resellers.</p>
        </div>
        <button type="button" class="btn btn-secondary" onclick="runReconciliation()">Run Invariant Check</button>
    </div>

    <div class="grid-4">
        <div class="panel" style="padding: 20px;">
            <div style="font-size: 12px; color: var(--text-muted); font-weight: 600;">TOTAL CIRCULATING CREDITS</div>
            <div style="font-size: 32px; font-weight: 700; color: #fff; margin-top: 6px;">{rec['total_circulating_credits']}</div>
        </div>
        <div class="panel" style="padding: 20px;">
            <div style="font-size: 12px; color: var(--text-muted); font-weight: 600;">ACTIVE RESELLERS</div>
            <div style="font-size: 32px; font-weight: 700; color: var(--primary); margin-top: 6px;">{rec['total_resellers']}</div>
        </div>
        <div class="panel" style="padding: 20px;">
            <div style="font-size: 12px; color: var(--text-muted); font-weight: 600;">LEDGER INVARIANT STATUS</div>
            <div style="font-size: 20px; font-weight: 700; color: { 'var(--success)' if rec['all_reconciled'] else 'var(--danger)' }; margin-top: 14px;">
                { 'All Reconciled (100%)' if rec['all_reconciled'] else f"{rec['total_discrepancies']} Discrepancies" }
            </div>
        </div>
        <div class="panel" style="padding: 20px;">
            <div style="font-size: 12px; color: var(--text-muted); font-weight: 600;">FIXED PRICING TIERS</div>
            <div style="font-size: 13px; color: var(--text-secondary); margin-top: 8px;">
                7d: 0.50 &middot; 15d: 1.00 &middot; 30d: 2.00
            </div>
        </div>
    </div>

    <div class="panel">
        <div class="panel-header">
            <span class="panel-title">Latest Platform Credit Journal Entries</span>
        </div>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Transaction ID</th>
                        <th>Seller</th>
                        <th>Type</th>
                        <th>Amount</th>
                        <th>Balance After</th>
                        <th>Description / Reason</th>
                        <th>Initiated By</th>
                        <th>Timestamp (UTC)</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
    </div>

    <script>
    async function runReconciliation() {{
        const resp = await fetch('/api/v1/admin/credits/reconcile');
        const data = await resp.json();
        if (data.all_reconciled) {{
            alert(`Reconciliation Passed!\nCirculating Credits: ${{data.total_circulating_credits}}\nAll ${{data.total_resellers}} reseller accounts match the append-only ledger exactly.`);
        }} else {{
            alert(`Reconciliation Warning: ${{data.total_discrepancies}} accounts had discrepancies! Check security logs.`);
        }}
    }}
    </script>
    """
    return HTMLResponse(content=render_admin_shell("Credit Ledger Hub", content, active_tab="credits"))

# -------------------------------------------------------------------------
# 4. TRANSACTIONS AUDIT VIEW (/admin/transactions)
# -------------------------------------------------------------------------
@router.get("/admin/transactions", response_class=HTMLResponse)
async def admin_transactions_page(request: Request, db: AsyncSession = Depends(get_db)):
    if not check_admin_html(request):
        return RedirectResponse(url="/admin/login", status_code=303)

    res_l = await db.execute(select(CreditLedger).order_by(CreditLedger.timestamp.desc()).limit(100))
    entries = res_l.scalars().all()

    rows_html = ""
    for e in entries:
        is_pos = (e.amount > 0)
        amt_str = f"+{e.amount:.2f}" if is_pos else f"{e.amount:.2f}"
        tone = "success" if is_pos else "purple"

        rows_html += f"""
        <tr>
            <td class="mono" style="font-size: 11px;">{e.transaction_id}</td>
            <td class="mono">Reseller #{e.seller_id}</td>
            <td><span class="status-badge status-{tone}">{e.transaction_type}</span></td>
            <td style="font-weight: 700; color: { 'var(--success)' if is_pos else '#fff' };">{amt_str}</td>
            <td>{e.balance_after:.2f}</td>
            <td class="mono" style="color: var(--primary);">{e.related_key or '—'}</td>
            <td>{e.description}</td>
            <td class="mono" style="font-size: 11px; color: var(--text-muted);">{e.correlation_id or '—'}</td>
            <td style="font-size: 11px; color: var(--text-muted);">{format_nepal_time(e.timestamp, '%Y-%m-%d %H:%M:%S')}</td>
        </tr>"""

    if not rows_html:
        rows_html = '<tr><td colspan="9" style="text-align:center; padding: 32px; color: var(--text-muted);">No transaction logs recorded.</td></tr>'

    content = f"""
    <div style="margin-bottom: 24px;">
        <h2 style="font-size: 20px; font-weight: 700; color: #fff;">Financial Transactions Audit Trail</h2>
        <p style="font-size: 13px; color: var(--text-secondary);">Complete end-to-end audit journal of every credit transaction with correlation IDs and related keys.</p>
    </div>

    <div class="panel">
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Transaction ID</th>
                        <th>Seller</th>
                        <th>Type</th>
                        <th>Amount</th>
                        <th>Balance After</th>
                        <th>Related Key</th>
                        <th>Reason / Notes</th>
                        <th>Correlation ID</th>
                        <th>Timestamp (NPT)</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
    </div>
    """
    return HTMLResponse(content=render_admin_shell("Transaction Audit", content, active_tab="transactions"))

# -------------------------------------------------------------------------
# 5. SECURITY CENTER VIEW (/admin/security)
# -------------------------------------------------------------------------
@router.get("/admin/security", response_class=HTMLResponse)
async def admin_security_page(request: Request, db: AsyncSession = Depends(get_db)):
    if not check_admin_html(request):
        return RedirectResponse(url="/admin/login", status_code=303)

    # Security audit events
    res_logs = await db.execute(
        select(AuditLog).where(
            AuditLog.action.in_([
                "ADMIN_LOGIN_SUCCESS", "ADMIN_LOGIN_FAILED", "CREDIT_ALLOCATE",
                "CREDIT_DEDUCT", "SELLER_KEY_GENERATE", "LOGIN_FAILED_INVALID_KEY",
                "HWID_MISMATCH_BLOCKED", "SPAM_RATE_LIMIT_TRIGGERED"
            ])
        ).order_by(AuditLog.timestamp.desc()).limit(50)
    )
    logs = res_logs.scalars().all()

    log_rows_html = ""
    for l in logs:
        tone = "success" if "SUCCESS" in l.action or "ALLOCATE" in l.action else ("danger" if "FAILED" in l.action or "BLOCKED" in l.action or "MISMATCH" in l.action or "SPAM" in l.action else "warning")
        clean_details = re.sub(r'(\b\d+\.\d{2})00\b', r'\1', l.details) if l.details else '—'
        log_rows_html += f"""
        <tr>
            <td style="font-size: 11.5px; color: var(--text-muted);">{format_nepal_time(l.timestamp, '%Y-%m-%d %H:%M:%S')}</td>
            <td><span class="status-badge status-{tone}">{l.action}</span></td>
            <td class="mono" style="font-size: 11px;">{l.ip_address or '—'}</td>
            <td class="mono" style="font-size: 11px;">{l.license_key or '—'}</td>
            <td style="font-size: 12.5px;">{clean_details}</td>
        </tr>"""

    if not log_rows_html:
        log_rows_html = '<tr><td colspan="5" style="text-align:center; padding: 24px; color: var(--text-muted);">No security alerts recorded.</td></tr>'

    content = f"""
    <div style="margin-bottom: 24px;">
        <h2 style="font-size: 20px; font-weight: 700; color: #fff;">Application Security & Integrity Center</h2>
        <p style="font-size: 13px; color: var(--text-secondary);">Monitor high-risk administrative operations, credential events, intrusion blocks, and rate-limiting triggers.</p>
    </div>

    <div class="grid-4">
        <div class="panel" style="padding: 20px;">
            <div style="font-size: 12px; color: var(--text-muted); font-weight: 600;">ENCRYPTION & STORAGE</div>
            <div style="font-size: 18px; font-weight: 700; color: var(--success); margin-top: 8px;">PBKDF2-SHA256</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">Zero plain-text password storage</div>
        </div>
        <div class="panel" style="padding: 20px;">
            <div style="font-size: 12px; color: var(--text-muted); font-weight: 600;">SESSION ISOLATION</div>
            <div style="font-size: 18px; font-weight: 700; color: #fff; margin-top: 8px;">Strict RBAC</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">Admin & Seller tokens separated</div>
        </div>
        <div class="panel" style="padding: 20px;">
            <div style="font-size: 12px; color: var(--text-muted); font-weight: 600;">IDOR / BOLA SHIELD</div>
            <div style="font-size: 18px; font-weight: 700; color: var(--success); margin-top: 8px;">Server-Enforced</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">Deny-by-default cross-seller isolation</div>
        </div>
        <div class="panel" style="padding: 20px;">
            <div style="font-size: 12px; color: var(--text-muted); font-weight: 600;">FINANCIAL PRECISION</div>
            <div style="font-size: 18px; font-weight: 700; color: var(--primary); margin-top: 8px;">Exact Decimal(4)</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">Zero float rounding errors</div>
        </div>
    </div>

    <div class="panel">
        <div class="panel-header">
            <span class="panel-title">Security & Sensitive Operations Log</span>
        </div>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Action</th>
                        <th>Origin IP</th>
                        <th>Key Reference</th>
                        <th>Security Details</th>
                    </tr>
                </thead>
                <tbody>
                    {log_rows_html}
                </tbody>
            </table>
        </div>
    </div>
    """
    return HTMLResponse(content=render_admin_shell("Security Audit Center", content, active_tab="security"))

# -------------------------------------------------------------------------
# 6. ADMIN REST APIS
# -------------------------------------------------------------------------
class CreateResellerRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    email: Optional[str] = None
    display_name: Optional[str] = None
    initial_credits: Optional[float] = 0.0

class CreditOperationRequest(BaseModel):
    amount: float = Field(..., gt=0)
    reason: str = Field(..., min_length=2, max_length=255)

class UpdateStatusRequest(BaseModel):
    status: str = Field(..., pattern="^(active|suspended|inactive)$")

@router.post("/api/v1/admin/resellers", dependencies=[Depends(require_admin)])
async def api_create_reseller(req: CreateResellerRequest, db: AsyncSession = Depends(get_db)):
    clean_username = req.username.strip().lower()
    res = await db.execute(select(Reseller).where(Reseller.username == clean_username))
    if res.scalars().first():
        raise HTTPException(status_code=400, detail=f"Username '{clean_username}' is already taken.")

    hashed_pw = pbkdf2_sha256.hash(req.password)
    init_credits = to_exact_credit(req.initial_credits or 0.0)
    display_name = req.display_name.strip() if req.display_name else clean_username

    reseller = Reseller(
        username=clean_username,
        password_hash=hashed_pw,
        display_name=display_name,
        email=req.email.strip() if req.email else None,
        status="active",
        credit_balance=init_credits,
        created_at=utc_now(),
        created_by="admin"
    )
    db.add(reseller)
    await db.commit()
    await db.refresh(reseller)

    if init_credits > Decimal("0.0000"):
        tx_id = f"tx_init_{uuid.uuid4().hex[:12]}"
        ledger = CreditLedger(
            transaction_id=tx_id,
            seller_id=reseller.id,
            transaction_type="ADMIN_ALLOCATE",
            amount=init_credits,
            balance_before=Decimal("0.0000"),
            balance_after=init_credits,
            description="Initial account creation credit allocation",
            related_key=None,
            related_customer_id=None,
            initiated_by="admin",
            timestamp=utc_now(),
            status="COMPLETED"
        )
        db.add(ledger)
        await db.commit()

    return {
        "success": True,
        "reseller": {
            "id": reseller.id,
            "username": reseller.username,
            "display_name": reseller.display_name,
            "credit_balance": str(reseller.credit_balance)
        }
    }

@router.post("/api/v1/admin/resellers/{seller_id}/status", dependencies=[Depends(require_admin)])
async def api_update_reseller_status(seller_id: int, req: UpdateStatusRequest, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Reseller).where(Reseller.id == seller_id))
    seller = res.scalars().first()
    if not seller:
        raise HTTPException(status_code=404, detail="Reseller not found.")

    old_status = seller.status
    seller.status = req.status
    log = AuditLog(
        action="SELLER_STATUS_CHANGED",
        details=f"Reseller '{seller.username}' (#{seller.id}) status changed from '{old_status}' to '{req.status}' by admin."
    )
    db.add(log)
    await db.commit()
    return {"success": True, "seller_id": seller.id, "status": seller.status}

@router.post("/api/v1/admin/resellers/{seller_id}/allocate-credits", dependencies=[Depends(require_admin)])
async def api_allocate_credits(seller_id: int, req: CreditOperationRequest, db: AsyncSession = Depends(get_db)):
    ledger, seller = await allocate_credits(
        db=db,
        seller_id=seller_id,
        amount=req.amount,
        reason=req.reason,
        initiated_by="admin"
    )
    return {
        "success": True,
        "transaction_id": ledger.transaction_id,
        "new_balance": str(seller.credit_balance),
        "amount_allocated": str(ledger.amount)
    }

@router.post("/api/v1/admin/resellers/{seller_id}/deduct-credits", dependencies=[Depends(require_admin)])
async def api_deduct_credits(seller_id: int, req: CreditOperationRequest, db: AsyncSession = Depends(get_db)):
    ledger, seller = await deduct_credits(
        db=db,
        seller_id=seller_id,
        amount=req.amount,
        reason=req.reason,
        initiated_by="admin"
    )
    return {
        "success": True,
        "transaction_id": ledger.transaction_id,
        "new_balance": str(seller.credit_balance),
        "amount_deducted": str(abs(ledger.amount))
    }

@router.get("/api/v1/admin/credits/reconcile", dependencies=[Depends(require_admin)])
async def api_reconcile_credits(db: AsyncSession = Depends(get_db)):
    return await reconcile_all_resellers(db)

# -------------------------------------------------------------------------
# 7. REAL-TIME WEBSOCKET FOR ADMIN
# -------------------------------------------------------------------------
@router.websocket("/ws/admin")
async def websocket_admin_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token") or websocket.cookies.get(settings.ADMIN_SESSION_COOKIE)
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("sub") != "admin":
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except Exception:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await realtime_hub.connect_admin_ws(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await realtime_hub.disconnect_admin_ws(websocket)
    except Exception:
        await realtime_hub.disconnect_admin_ws(websocket)
