"""Audit planning, evidence ingestion, and deterministic policy decisions."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.audit_run import (
    AuditFindingCreate,
    AuditFindingResponse,
    AuditPlanCreate,
    AuditRunResponse,
    AuditTraceResponse,
)
from app.services.audit_service import (
    AuditNotFoundError,
    AuditService,
    SecurityRuleNotFoundError,
)

router = APIRouter(prefix="/audits", tags=["Audits & Policy"])
audit_service = AuditService()


@router.post("/plan", response_model=AuditRunResponse, status_code=status.HTTP_201_CREATED)
async def create_audit_plan(
    plan: AuditPlanCreate, db: AsyncSession = Depends(get_db)
):
    """Create an auditable plan without running any scanner."""
    try:
        return await audit_service.create_plan(plan, db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{audit_id}", response_model=AuditRunResponse)
async def get_audit(audit_id: UUID, db: AsyncSession = Depends(get_db)):
    """Return status and policy decision for a single audit."""
    audit = await audit_service.get_audit(audit_id, db)
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit not found")
    return audit


@router.post(
    "/{audit_id}/findings",
    response_model=AuditFindingResponse,
    status_code=status.HTTP_201_CREATED,
)
async def attach_finding(
    audit_id: UUID,
    incoming: AuditFindingCreate,
    db: AsyncSession = Depends(get_db),
):
    """Persist scanner evidence, normalize it, and apply deterministic policy."""
    try:
        return await audit_service.attach_finding(audit_id, incoming, db)
    except (AuditNotFoundError, SecurityRuleNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{audit_id}/trace", response_model=AuditTraceResponse)
async def get_audit_trace(audit_id: UUID, db: AsyncSession = Depends(get_db)):
    """Return evidence, normalized context, policy result, and audit lifecycle."""
    audit = await audit_service.get_audit(audit_id, db)
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit not found")
    return audit

