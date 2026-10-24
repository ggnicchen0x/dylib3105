import uuid
import datetime
import logging
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from typing import Optional, Dict, Any, Tuple
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func

from database.models import Reseller, Customer, CreditLedger, License, AuditLog, IdempotencyRecord, utc_now
from services.license import generate_random_license_key
from services.realtime import realtime_hub

logger = logging.getLogger("auth_gateway.credit")

# -------------------------------------------------------------------------
# CENTRAL CREDIT PRICING & PRECISION DEFINITION
# -------------------------------------------------------------------------
CREDIT_PRECISION = 4
CREDIT_QUANTIZER = Decimal("0.0001")
PRICING_VERSION = "v1.0-fixed"

# Strict fixed pricing table (duration_days -> Decimal cost)
FIXED_DURATION_PRICING: Dict[int, Decimal] = {
    7: Decimal("0.5000"),
    15: Decimal("1.0000"),
    30: Decimal("2.0000"),
}

def to_exact_credit(val: Any) -> Decimal:
    """
    Guarantees conversion to Decimal with strict 4 decimal places precision.
    Rejects floating point inaccuracies and malformed inputs.
    """
    if val is None:
        return Decimal("0.0000")
    try:
        if isinstance(val, (int, str)):
            d = Decimal(str(val))
        elif isinstance(val, Decimal):
            d = val
        else:
            # If float or other, convert via string to avoid binary float artifacts
            d = Decimal(str(val))
        return d.quantize(CREDIT_QUANTIZER, rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError, TypeError) as e:
        raise ValueError(f"Invalid credit value: {val} ({e})")

def get_duration_pricing(duration_days: int) -> Decimal:
    """
    Retrieves required credit cost for the requested duration.
    Rejects unsupported durations with 400 Bad Request.
    """
    if duration_days not in FIXED_DURATION_PRICING:
        allowed = ", ".join(f"{d} days ({cost} credits)" for d, cost in FIXED_DURATION_PRICING.items())
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported license duration '{duration_days}' days. Supported durations are: {allowed}."
        )
    return FIXED_DURATION_PRICING[duration_days]

# -------------------------------------------------------------------------
# ATOMIC LEDGER RECORDING & BALANCE MANAGEMENT
# -------------------------------------------------------------------------
async def allocate_credits(
    db: AsyncSession,
    seller_id: int,
    amount: Any,
    reason: str,
    initiated_by: str = "admin",
    correlation_id: Optional[str] = None
) -> Tuple[CreditLedger, Reseller]:
    """
    Admin allocation of credits to a reseller.
    Executes in an atomic database transaction with immutable ledger insertion.
    """
    exact_amount = to_exact_credit(amount)
    if exact_amount <= Decimal("0.0000"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Allocation credit amount must be strictly greater than 0."
        )

    res = await db.execute(select(Reseller).where(Reseller.id == seller_id))
    seller = res.scalars().first()
    if not seller:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reseller account not found.")

    balance_before = to_exact_credit(seller.credit_balance)
    balance_after = (balance_before + exact_amount).quantize(CREDIT_QUANTIZER)
    seller.credit_balance = balance_after

    tx_id = f"tx_alloc_{uuid.uuid4().hex[:12]}"
    corr_id = correlation_id or f"corr_{uuid.uuid4().hex[:8]}"

    ledger = CreditLedger(
        transaction_id=tx_id,
        seller_id=seller.id,
        transaction_type="ADMIN_ALLOCATE",
        amount=exact_amount,
        balance_before=balance_before,
        balance_after=balance_after,
        description=reason.strip() or "Administrative credit allocation",
        related_key=None,
        related_customer_id=None,
        initiated_by=initiated_by,
        timestamp=utc_now(),
        status="COMPLETED",
        idempotency_key=None,
        correlation_id=corr_id
    )
    db.add(ledger)

    audit = AuditLog(
        action="CREDIT_ALLOCATE",
        ip_address=None,
        details=f"Admin '{initiated_by}' allocated {exact_amount:.2f} credits to reseller '{seller.username}' (#{seller.id}). New balance: {balance_after:.2f}."
    )
    db.add(audit)

    await db.commit()
    await db.refresh(seller)
    await db.refresh(ledger)

    # Publish real-time event to seller & admin
    await realtime_hub.dispatch_seller_event(seller.id, "BALANCE_UPDATED", {
        "event": "CREDIT_ALLOCATED",
        "amount": str(exact_amount),
        "balance": str(balance_after),
        "reason": ledger.description,
        "transaction_id": tx_id
    })
    await realtime_hub.dispatch_admin_event("CREDIT_ALLOCATED", {
        "seller_id": seller.id,
        "seller_username": seller.username,
        "amount": str(exact_amount),
        "new_balance": str(balance_after),
        "transaction_id": tx_id
    })

    return ledger, seller

async def deduct_credits(
    db: AsyncSession,
    seller_id: int,
    amount: Any,
    reason: str,
    initiated_by: str = "admin",
    correlation_id: Optional[str] = None
) -> Tuple[CreditLedger, Reseller]:
    """
    Administrative deduction of credits from a reseller with mandatory reason.
    Prevents negative balance unless an administrative override is explicitly defined.
    """
    exact_amount = to_exact_credit(amount)
    if exact_amount <= Decimal("0.0000"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Deduction credit amount must be strictly greater than 0."
        )

    if not reason or not reason.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mandatory reason is required for administrative credit deduction."
        )

    res = await db.execute(select(Reseller).where(Reseller.id == seller_id))
    seller = res.scalars().first()
    if not seller:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reseller account not found.")

    balance_before = to_exact_credit(seller.credit_balance)
    if balance_before < exact_amount:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot deduct {exact_amount} credits: reseller current balance is only {balance_before}."
        )

    balance_after = (balance_before - exact_amount).quantize(CREDIT_QUANTIZER)
    seller.credit_balance = balance_after

    tx_id = f"tx_deduct_{uuid.uuid4().hex[:12]}"
    corr_id = correlation_id or f"corr_{uuid.uuid4().hex[:8]}"

    ledger = CreditLedger(
        transaction_id=tx_id,
        seller_id=seller.id,
        transaction_type="ADMIN_DEDUCT",
        amount=-exact_amount, # Negative sign for debit
        balance_before=balance_before,
        balance_after=balance_after,
        description=reason.strip(),
        related_key=None,
        related_customer_id=None,
        initiated_by=initiated_by,
        timestamp=utc_now(),
        status="COMPLETED",
        idempotency_key=None,
        correlation_id=corr_id
    )
    db.add(ledger)

    audit = AuditLog(
        action="CREDIT_DEDUCT",
        ip_address=None,
        details=f"Admin '{initiated_by}' deducted {exact_amount:.2f} credits from reseller '{seller.username}' (#{seller.id}). Reason: {reason}. New balance: {balance_after:.2f}."
    )
    db.add(audit)

    await db.commit()
    await db.refresh(seller)
    await db.refresh(ledger)

    # Publish real-time event
    await realtime_hub.dispatch_seller_event(seller.id, "BALANCE_UPDATED", {
        "event": "CREDIT_DEDUCTED",
        "amount": f"-{exact_amount}",
        "balance": str(balance_after),
        "reason": ledger.description,
        "transaction_id": tx_id
    })
    await realtime_hub.dispatch_admin_event("CREDIT_DEDUCTED", {
        "seller_id": seller.id,
        "seller_username": seller.username,
        "amount": str(exact_amount),
        "new_balance": str(balance_after),
        "transaction_id": tx_id
    })

    return ledger, seller

# -------------------------------------------------------------------------
# ATOMIC RESELLER KEY GENERATION
# -------------------------------------------------------------------------
async def atomic_generate_reseller_key(
    db: AsyncSession,
    seller_id: int,
    duration_days: int,
    customer_id: Optional[int] = None,
    new_customer_name: Optional[str] = None,
    new_customer_contact: Optional[str] = None,
    prefix: str = "BYTE",
    notes: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    client_ip: Optional[str] = None
) -> Dict[str, Any]:
    """
    Atomically generates a license key for a seller:
    1. Authenticate and check active seller status.
    2. Validate duration and get server-controlled credit cost.
    3. Idempotency check: if key already used by this seller, return stored response.
    4. Validate / create customer with server-enforced ownership.
    5. Debit credits atomically, create License, insert CreditLedger, record AuditLog.
    6. Commit database transaction.
    7. Dispatch real-time updates.
    """
    # 1. Check idempotency
    clean_idem = idempotency_key.strip() if idempotency_key else None
    if clean_idem:
        res_idem = await db.execute(
            select(IdempotencyRecord).where(
                IdempotencyRecord.idempotency_key == clean_idem,
                IdempotencyRecord.seller_id == seller_id
            )
        )
        existing_idem = res_idem.scalars().first()
        if existing_idem:
            import json
            logger.info(f"[IDEMPOTENCY] Replaying cached response for key {clean_idem}")
            return json.loads(existing_idem.response_body)

    # 2. Validate reseller status
    res = await db.execute(select(Reseller).where(Reseller.id == seller_id))
    seller = res.scalars().first()
    if not seller:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reseller not found.")

    if seller.status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Reseller account is currently {seller.status}. Key generation is prohibited."
        )

    # 3. Retrieve server-enforced cost
    cost = get_duration_pricing(duration_days)

    # 4. Check balance
    balance_before = to_exact_credit(seller.credit_balance)
    if balance_before < cost:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Insufficient credit balance: Required {cost} credits, but current balance is {balance_before} credits."
        )

    # 5. Customer resolution & ownership check
    target_customer = None
    if customer_id:
        res_c = await db.execute(
            select(Customer).where(Customer.id == customer_id, Customer.seller_id == seller.id)
        )
        target_customer = res_c.scalars().first()
        if not target_customer:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Customer not found or belongs to another reseller (access denied)."
            )
    elif new_customer_name and new_customer_name.strip():
        # Create customer for this seller
        cust_code = f"CUST-{uuid.uuid4().hex[:8].upper()}"
        target_customer = Customer(
            seller_id=seller.id,
            customer_code=cust_code,
            name=new_customer_name.strip()[:100],
            contact=(new_customer_contact or "").strip()[:120] if new_customer_contact else None,
            status="active",
            notes="Auto-created during key generation",
            created_at=utc_now()
        )
        db.add(target_customer)
        await db.flush() # assign target_customer.id

    # 6. Atomic Debit & Key Creation
    balance_after = (balance_before - cost).quantize(CREDIT_QUANTIZER)
    seller.credit_balance = balance_after

    raw_key = generate_random_license_key(prefix=prefix or "BYTE")
    tier_label = f"{duration_days}d"
    key_note = (notes or f"Reseller key for {target_customer.name if target_customer else 'Customer'}").strip()[:255]

    lic = License(
        key=raw_key,
        status="active",
        bound_device_hash=None,
        duration_days=duration_days,
        created_at=utc_now(),
        activated_at=None,
        expires_at=None,
        notes=key_note,
        seller_id=seller.id,
        customer_id=target_customer.id if target_customer else None,
        generated_by="reseller",
        pricing_tier=tier_label
    )
    db.add(lic)

    tx_id = f"tx_gen_{uuid.uuid4().hex[:12]}"
    corr_id = f"corr_gen_{uuid.uuid4().hex[:8]}"

    desc = f"Added key: {raw_key} ({duration_days}d, {cost:.2f} credits)"
    if target_customer:
        desc += f" for customer {target_customer.name}"

    ledger = CreditLedger(
        transaction_id=tx_id,
        seller_id=seller.id,
        transaction_type="KEY_GENERATE",
        amount=-cost,
        balance_before=balance_before,
        balance_after=balance_after,
        description=desc,
        related_key=raw_key,
        related_customer_id=target_customer.id if target_customer else None,
        initiated_by=seller.username,
        timestamp=utc_now(),
        status="COMPLETED",
        idempotency_key=clean_idem,
        correlation_id=corr_id
    )
    db.add(ledger)

    audit = AuditLog(
        action="SELLER_KEY_GENERATE",
        ip_address=client_ip,
        license_key=raw_key,
        details=f"Seller '{seller.username}' generated {duration_days}-day key. Cost: {cost:.2f}. Prev balance: {balance_before:.2f}, new balance: {balance_after:.2f}."
    )
    db.add(audit)

    result_data = {
        "success": True,
        "key": raw_key,
        "duration_days": duration_days,
        "cost": str(cost),
        "balance_before": str(balance_before),
        "balance_after": str(balance_after),
        "pricing_version": PRICING_VERSION,
        "customer": {
            "id": target_customer.id,
            "code": target_customer.customer_code,
            "name": target_customer.name
        } if target_customer else None,
        "transaction_id": tx_id,
        "created_at": utc_now().isoformat()
    }

    # Record idempotency
    if clean_idem:
        import json
        idem_rec = IdempotencyRecord(
            idempotency_key=clean_idem,
            seller_id=seller.id,
            endpoint="/api/v1/seller/keys/generate",
            response_status=200,
            response_body=json.dumps(result_data),
            created_at=utc_now()
        )
        db.add(idem_rec)

    await db.commit()

    # 7. Real-time updates
    await realtime_hub.dispatch_seller_event(seller.id, "KEY_GENERATED", {
        "key": raw_key,
        "duration_days": duration_days,
        "cost": str(cost),
        "balance": str(balance_after),
        "transaction_id": tx_id
    })
    await realtime_hub.dispatch_admin_event("SELLER_KEY_GENERATED", {
        "seller_id": seller.id,
        "seller_username": seller.username,
        "key": raw_key,
        "duration_days": duration_days,
        "cost": str(cost),
        "new_balance": str(balance_after)
    })

    return result_data

# -------------------------------------------------------------------------
# RECONCILIATION & AUDIT VERIFICATION
# -------------------------------------------------------------------------
async def reconcile_seller_credits(db: AsyncSession, seller_id: int) -> Dict[str, Any]:
    """
    Computes sum of all append-only ledger entries for a seller and compares
    against seller's current cached balance.
    Invariant: seller.credit_balance == sum(ledger.amount)
    """
    res = await db.execute(select(Reseller).where(Reseller.id == seller_id))
    seller = res.scalars().first()
    if not seller:
        raise HTTPException(status_code=404, detail="Reseller not found.")

    res_sum = await db.execute(
        select(func.coalesce(func.sum(CreditLedger.amount), 0)).where(CreditLedger.seller_id == seller.id)
    )
    raw_sum = res_sum.scalar()
    ledger_sum = to_exact_credit(raw_sum)
    current_balance = to_exact_credit(seller.credit_balance)

    res_keys = await db.execute(
        select(func.count(License.id)).where(License.seller_id == seller.id)
    )
    total_keys = res_keys.scalar() or 0

    is_reconciled = (ledger_sum == current_balance)

    return {
        "seller_id": seller.id,
        "username": seller.username,
        "current_balance": f"{current_balance:.2f}",
        "ledger_sum": f"{ledger_sum:.2f}",
        "discrepancy": f"{(current_balance - ledger_sum):.2f}",
        "is_reconciled": is_reconciled,
        "total_issued_keys": total_keys
    }

async def reconcile_all_resellers(db: AsyncSession) -> Dict[str, Any]:
    """
    Reconciles all resellers platform-wide.
    """
    res = await db.execute(select(Reseller))
    resellers = res.scalars().all()

    reports = []
    total_circulating = Decimal("0.0000")
    total_discrepancies = 0

    for s in resellers:
        rep = await reconcile_seller_credits(db, s.id)
        reports.append(rep)
        total_circulating += to_exact_credit(s.credit_balance)
        if not rep["is_reconciled"]:
            total_discrepancies += 1

    return {
        "total_resellers": len(resellers),
        "total_circulating_credits": f"{total_circulating:.2f}",
        "total_discrepancies": total_discrepancies,
        "all_reconciled": (total_discrepancies == 0),
        "reports": reports
    }
