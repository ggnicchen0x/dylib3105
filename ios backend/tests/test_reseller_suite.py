import os
import pytest
import asyncio
from decimal import Decimal
from fastapi.testclient import TestClient
from passlib.hash import pbkdf2_sha256
from sqlalchemy.future import select

import main
from database.models import init_db, get_db, Reseller, Customer, CreditLedger, License, AsyncSessionLocal
from routes.seller_routes import create_seller_jwt
from config import settings

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

@pytest.fixture(scope="session", autouse=True)
def prepare_database():
    asyncio.run(init_db())
    yield
    async def cleanup_test_artifacts():
        async with AsyncSessionLocal() as db:
            await db.execute(delete(CreditLedger).where(CreditLedger.initiated_by.like("seller_%") | (CreditLedger.seller_id.isnot(None))))
            await db.execute(delete(License).where(License.generated_by == "reseller"))
            await db.execute(delete(Customer).where(Customer.seller_id.isnot(None)))
            await db.execute(delete(Reseller).where(Reseller.created_by == "test"))
            await db.commit()
    asyncio.run(cleanup_test_artifacts())

@pytest.fixture
def client():
    return TestClient(main.app, follow_redirects=False)

def get_admin_headers():
    return {"x-admin-key": settings.ADMIN_API_KEY}

import uuid
from sqlalchemy import delete

async def create_test_reseller(username: str, balance: float = 10.0, status: str = "active") -> Reseller:
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Reseller).where(Reseller.username == username))
        existing = res.scalars().first()
        if existing:
            existing.credit_balance = Decimal(str(balance))
            existing.status = status
            existing.password_hash = pbkdf2_sha256.hash("test_password_123")
            await db.execute(delete(CreditLedger).where(CreditLedger.seller_id == existing.id))
            await db.commit()
            await db.refresh(existing)
            return existing

        seller = Reseller(
            username=username,
            password_hash=pbkdf2_sha256.hash("test_password_123"),
            display_name=f"Test {username.title()}",
            email=f"{username}@example.com",
            status=status,
            credit_balance=Decimal(str(balance)),
            created_by="test"
        )
        db.add(seller)
        await db.commit()
        await db.refresh(seller)
        return seller

# -----------------------------------------------------------------------------
# 1. ROUTE ISOLATION & UNAUTHENTICATED PROTECTION
# -----------------------------------------------------------------------------
def test_unauthenticated_seller_routes_redirect(client):
    protected_seller_routes = [
        "/seller/dashboard",
        "/seller/users",
        "/seller/keys",
        "/seller/credits",
        "/seller/profile"
    ]
    for r in protected_seller_routes:
        resp = client.get(r)
        assert resp.status_code == 303
        assert resp.headers.get("location") == "/seller/login"

def test_unauthenticated_admin_routes_redirect(client):
    protected_admin_routes = [
        "/admin/resellers",
        "/admin/credits",
        "/admin/transactions",
        "/admin/security"
    ]
    for r in protected_admin_routes:
        resp = client.get(r)
        assert resp.status_code == 303
        assert resp.headers.get("location") == "/admin/login"

def test_seller_cannot_access_admin_api(client):
    seller = asyncio.run(create_test_reseller("seller_intruder", balance=5.0))
    token = create_seller_jwt(seller)

    # Attempt to access admin API with seller token
    resp = client.get(
        "/api/v1/admin/credits/reconcile",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code in (401, 403)

# -----------------------------------------------------------------------------
# 2. FIXED CREDIT PRICING & QUANTITY RULES
# -----------------------------------------------------------------------------
def test_fixed_pricing_rules(client):
    seller = asyncio.run(create_test_reseller("seller_pricing_test", balance=20.0))
    token = create_seller_jwt(seller)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # 7 Days -> 0.5 Credits
    resp7 = client.post(
        "/api/v1/seller/keys/generate",
        headers=headers,
        json={"duration_days": 7, "notes": "7-day test"}
    )
    assert resp7.status_code == 200
    data7 = resp7.json()
    assert data7["cost"] == "0.5000"
    assert data7["duration_days"] == 7

    # 15 Days -> 1.0 Credit
    resp15 = client.post(
        "/api/v1/seller/keys/generate",
        headers=headers,
        json={"duration_days": 15, "notes": "15-day test"}
    )
    assert resp15.status_code == 200
    data15 = resp15.json()
    assert data15["cost"] == "1.0000"
    assert data15["duration_days"] == 15

    # 30 Days -> 2.0 Credits
    resp30 = client.post(
        "/api/v1/seller/keys/generate",
        headers=headers,
        json={"duration_days": 30, "notes": "30-day test"}
    )
    assert resp30.status_code == 200
    data30 = resp30.json()
    assert data30["cost"] == "2.0000"
    assert data30["duration_days"] == 30

def test_unsupported_durations_strictly_rejected(client):
    seller = asyncio.run(create_test_reseller("seller_invalid_dur", balance=50.0))
    token = create_seller_jwt(seller)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    unsupported = [0, -7, 1, 5, 10, 20, 60, 365]
    for d in unsupported:
        resp = client.post(
            "/api/v1/seller/keys/generate",
            headers=headers,
            json={"duration_days": d}
        )
        assert resp.status_code == 400
        assert "Unsupported license duration" in resp.json()["detail"]

# -----------------------------------------------------------------------------
# 3. BALANCE SUFFICIENCY & OVERDRAFT PROTECTION
# -----------------------------------------------------------------------------
def test_insufficient_balance_rejected(client):
    # Reseller has only 0.4 credits (cannot afford 7-day which costs 0.5)
    seller = asyncio.run(create_test_reseller("seller_broke", balance=0.4))
    token = create_seller_jwt(seller)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    resp = client.post(
        "/api/v1/seller/keys/generate",
        headers=headers,
        json={"duration_days": 7}
    )
    assert resp.status_code == 400
    assert "Insufficient credit balance" in resp.json()["detail"]

# -----------------------------------------------------------------------------
# 4. IDEMPOTENCY KEY PROTECTION
# -----------------------------------------------------------------------------
def test_idempotent_key_generation(client):
    seller = asyncio.run(create_test_reseller("seller_idem", balance=10.0))
    token = create_seller_jwt(seller)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    idem_key = f"unique_idem_{uuid.uuid4().hex[:10]}"

    # First request
    resp1 = client.post(
        "/api/v1/seller/keys/generate",
        headers=headers,
        json={"duration_days": 7, "idempotency_key": idem_key}
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    created_key = data1["key"]
    balance_after_1 = data1["balance_after"]

    # Retry duplicate request with exact same idempotency_key
    resp2 = client.post(
        "/api/v1/seller/keys/generate",
        headers=headers,
        json={"duration_days": 7, "idempotency_key": idem_key}
    )
    assert resp2.status_code == 200
    data2 = resp2.json()

    # Must return exact same key and not debit balance a second time
    assert data2["key"] == created_key
    assert data2["balance_after"] == balance_after_1

# -----------------------------------------------------------------------------
# 5. IDOR / CROSS-SELLER DATA ACCESS PREVENTION
# -----------------------------------------------------------------------------
def test_seller_cannot_access_or_assign_other_seller_customer(client):
    seller_a = asyncio.run(create_test_reseller("seller_alpha", balance=10.0))
    seller_b = asyncio.run(create_test_reseller("seller_bravo", balance=10.0))

    # Create customer under Seller B
    async def create_cust_b():
        async with AsyncSessionLocal() as db:
            c = Customer(
                seller_id=seller_b.id,
                customer_code=f"CUST-BRAVO-{uuid.uuid4().hex[:6].upper()}",
                name="Bravo Client",
                status="active"
            )
            db.add(c)
            await db.commit()
            await db.refresh(c)
            return c.id

    cust_b_id = asyncio.run(create_cust_b())

    # Seller A attempts to generate a key using Seller B's customer_id
    token_a = create_seller_jwt(seller_a)
    headers_a = {"Authorization": f"Bearer {token_a}", "Content-Type": "application/json"}

    resp = client.post(
        "/api/v1/seller/keys/generate",
        headers=headers_a,
        json={"duration_days": 7, "customer_id": cust_b_id}
    )
    # Server-enforced ownership must block this IDOR attempt with 403 Forbidden
    assert resp.status_code == 403
    assert "belongs to another reseller" in resp.json()["detail"]

# -----------------------------------------------------------------------------
# 6. ADMIN CREDIT ALLOCATION & DEDUCTION WITH MANDATORY REASON
# -----------------------------------------------------------------------------
def test_admin_credit_allocation_and_deduction(client):
    seller = asyncio.run(create_test_reseller("seller_admin_ops", balance=5.0))
    admin_hdr = get_admin_headers()

    # 1. Allocate credits
    alloc_resp = client.post(
        f"/api/v1/admin/resellers/{seller.id}/allocate-credits",
        headers=admin_hdr,
        json={"amount": 25.5, "reason": "Monthly reseller prepaid deposit"}
    )
    assert alloc_resp.status_code == 200
    assert float(alloc_resp.json()["new_balance"]) == 30.5

    # 2. Deduct credits without reason -> MUST FAIL
    deduct_fail = client.post(
        f"/api/v1/admin/resellers/{seller.id}/deduct-credits",
        headers=admin_hdr,
        json={"amount": 5.0, "reason": ""}
    )
    assert deduct_fail.status_code == 422 # Pydantic min_length validation

    # 3. Deduct credits with valid reason
    deduct_resp = client.post(
        f"/api/v1/admin/resellers/{seller.id}/deduct-credits",
        headers=admin_hdr,
        json={"amount": 10.5, "reason": "Administrative adjustment"}
    )
    assert deduct_resp.status_code == 200
    assert float(deduct_resp.json()["new_balance"]) == 20.0

# -----------------------------------------------------------------------------
# 7. LEDGER IMMUTABILITY & RECONCILIATION INVARIANT
# -----------------------------------------------------------------------------
def test_ledger_accounting_invariant_reconciliation(client):
    seller = asyncio.run(create_test_reseller("seller_recon_test", balance=0.0))
    admin_hdr = get_admin_headers()
    token = create_seller_jwt(seller)
    seller_hdr = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # 1. Admin allocates 10.0 credits
    client.post(
        f"/api/v1/admin/resellers/{seller.id}/allocate-credits",
        headers=admin_hdr,
        json={"amount": 10.0, "reason": "Deposit"}
    )

    # 2. Seller generates 7-day key (-0.5)
    client.post(
        "/api/v1/seller/keys/generate",
        headers=seller_hdr,
        json={"duration_days": 7}
    )

    # 3. Seller generates 30-day key (-2.0)
    client.post(
        "/api/v1/seller/keys/generate",
        headers=seller_hdr,
        json={"duration_days": 30}
    )

    # 4. Admin deducts 1.5 credits (-1.5)
    client.post(
        f"/api/v1/admin/resellers/{seller.id}/deduct-credits",
        headers=admin_hdr,
        json={"amount": 1.5, "reason": "Adjustment"}
    )

    # Expected: 10.0 - 0.5 - 2.0 - 1.5 = 6.0000 credits
    recon_resp = client.get("/api/v1/admin/credits/reconcile", headers=admin_hdr)
    assert recon_resp.status_code == 200
    data = recon_resp.json()

    # Find this reseller in reconciliation reports
    seller_rep = next(r for r in data["reports"] if r["seller_id"] == seller.id)
    assert seller_rep["is_reconciled"] is True
    assert float(seller_rep["current_balance"]) == 6.0
    assert float(seller_rep["ledger_sum"]) == 6.0
    assert float(seller_rep["discrepancy"]) == 0.0

# -----------------------------------------------------------------------------
# 8. SUSPENDED SELLER LOCKED OUT FROM KEY ISSUANCE
# -----------------------------------------------------------------------------
def test_suspended_seller_locked_out(client):
    seller = asyncio.run(create_test_reseller("seller_suspended_test", balance=10.0, status="suspended"))
    token = create_seller_jwt(seller)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    resp = client.post(
        "/api/v1/seller/keys/generate",
        headers=headers,
        json={"duration_days": 7}
    )
    assert resp.status_code == 403
    assert "suspended" in resp.json()["detail"].lower()

# -----------------------------------------------------------------------------
# 9. PASSWORD CHANGE SECURITY
# -----------------------------------------------------------------------------
def test_seller_password_change(client):
    seller = asyncio.run(create_test_reseller("seller_pwd_test", balance=5.0))
    token = create_seller_jwt(seller)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Incorrect current password fails
    resp_fail = client.post(
        "/api/v1/seller/change-password",
        headers=headers,
        json={"current_password": "wrong_password", "new_password": "brand_new_secret_123"}
    )
    assert resp_fail.status_code == 400
    assert "failed" in resp_fail.json()["detail"].lower()

    # Correct current password succeeds
    resp_ok = client.post(
        "/api/v1/seller/change-password",
        headers=headers,
        json={"current_password": "test_password_123", "new_password": "brand_new_secret_123"}
    )
    assert resp_ok.status_code == 200
    assert resp_ok.json()["success"] is True

# -----------------------------------------------------------------------------
# 10. CSV EXPORT ISOLATION
# -----------------------------------------------------------------------------
def test_seller_keys_csv_export(client):
    seller = asyncio.run(create_test_reseller("seller_export_test", balance=5.0))
    token = create_seller_jwt(seller)
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/seller/keys/export", headers=headers)
    assert resp.status_code == 200
    assert resp.headers.get("content-type") == "text/csv; charset=utf-8"
    assert "License Key,Duration Days,Status" in resp.text
# -----------------------------------------------------------------------------
# 11. ADMIN TO SELLER VERSION SYNCHRONIZATION
# -----------------------------------------------------------------------------
def test_admin_to_seller_version_synchronization(client):
    seller = asyncio.run(create_test_reseller("seller_version_sync_test", balance=10.0))
    token = create_seller_jwt(seller)
    
    # 1. Admin updates version from 1.1.4 to 1.1.5
    admin_token = main.create_admin_token()
    client.cookies.set(settings.ADMIN_SESSION_COOKIE, admin_token)
    resp_update = client.post(
        "/admin/version",
        data={
            "app_version": "1.1.5",
            "force_update": "true",
            "download_url": "https://github.com/nicchen0xf/Swift-ios/releases/v1.1.5",
            "release_notes": "Official Release v1.1.5: Sync test"
        },
        follow_redirects=True
    )
    assert resp_update.status_code == 200

    # 2. Seller visits dashboard - must immediately display 1.1.5
    client.cookies.set(settings.SELLER_SESSION_COOKIE, token)
    resp_dash = client.get("/seller/dashboard")
    assert resp_dash.status_code == 200
    assert 'id="liveAppVersionVal"' in resp_dash.text
    assert ">1.1.5</div>" in resp_dash.text

    # 3. Seller visits releases/versions page - must display v1.1.5
    resp_ver = client.get("/seller/versions")
    assert resp_ver.status_code == 200
    assert "Current Production Gateway Version: v1.1.5" in resp_ver.text

    # 4. Admin resets version back to 1.1.4
    client.cookies.set(settings.ADMIN_SESSION_COOKIE, admin_token)
    resp_reset = client.post(
        "/admin/version",
        data={
            "app_version": "1.1.4",
            "force_update": "true",
            "download_url": "https://github.com/nicchen0xf/Swift-ios/releases/download/v1.1.4/ByteExternal_V1.1.4.ipa",
            "release_notes": "Official Release v1.1.4"
        },
        follow_redirects=True
    )
    assert resp_reset.status_code == 200

    # Seller dashboard reflects 1.1.4
    client.cookies.set(settings.SELLER_SESSION_COOKIE, token)
    resp_dash2 = client.get("/seller/dashboard")
    assert resp_dash2.status_code == 200
    assert ">1.1.4</div>" in resp_dash2.text
