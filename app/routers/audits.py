"""Audit planning, evidence ingestion, and deterministic policy decisions."""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import AuditFinding, AuditRun, Finding, SecurityRule
from app.schemas.audit_run import (
    AuditFindingCreate,
    AuditFindingResponse,
    AuditPlanCreate,
    AuditRunResponse,
    AuditTraceResponse,
)
from app.services.normalization_service import normalize_finding
from app.services.policy_service import PolicyResult, aggregate_actions, evaluate_finding

router = APIRouter(prefix="/audits", tags=["Audits & Policy"])


async def _get_audit(audit_id: UUID, db: AsyncSession) -> AuditRun:
    result = await db.execute(
        select(AuditRun)
        .options(selectinload(AuditRun.audit_findings).selectinload(AuditFinding.finding))
        .where(AuditRun.id == audit_id)
    )
    audit = result.scalar_one_or_none()
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit not found")
    return audit


def _update_audit_decision(audit: AuditRun) -> None:
    results = [
        PolicyResult(item.policy_action, item.policy_reason)
        for item in audit.audit_findings
    ]
    outcome = aggregate_actions(results)
    audit.decision = outcome.action
    audit.policy_reason = outcome.reason
    audit.status = "completed"
    audit.completed_at = datetime.now(timezone.utc)


@router.post("/plan", response_model=AuditRunResponse, status_code=status.HTTP_201_CREATED)
async def create_audit_plan(
    plan: AuditPlanCreate, db: AsyncSession = Depends(get_db)
):
    """Create an auditable plan without running any scanner."""
    if plan.scan_type in {"dast", "full"} and not plan.dast_authorized:
        raise HTTPException(
            status_code=400,
            detail="DAST requires explicit authorization for the target.",
        )
    audit = AuditRun(
        target=plan.target,
        scan_type=plan.scan_type,
        dast_authorized=plan.dast_authorized,
    )
    db.add(audit)
    await db.flush()
    return audit


@router.get("/{audit_id}", response_model=AuditRunResponse)
async def get_audit(audit_id: UUID, db: AsyncSession = Depends(get_db)):
    """Return status and policy decision for a single audit."""
    return await _get_audit(audit_id, db)


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
    audit = await _get_audit(audit_id, db)

    security_rule = None
    if incoming.security_rule_id:
        security_rule = await db.get(SecurityRule, incoming.security_rule_id)
        if security_rule is None:
            raise HTTPException(status_code=404, detail="Security rule not found")

    finding = Finding(source=incoming.source, raw_payload=incoming.raw_payload)
    db.add(finding)
    await db.flush()

    normalized = normalize_finding(incoming.source, incoming.raw_payload)
    policy = evaluate_finding(normalized)
    audit_finding = AuditFinding(
        audit_run_id=audit.id,
        finding_id=finding.id,
        security_rule_id=security_rule.id if security_rule else None,
        normalized_payload=normalized,
        policy_action=policy.action,
        policy_reason=policy.reason,
    )
    audit_finding.finding = finding
    db.add(audit_finding)
    audit.audit_findings.append(audit_finding)
    audit.status = "running"
    await db.flush()
    _update_audit_decision(audit)
    await db.flush()

    return audit_finding


@router.get("/{audit_id}/trace", response_model=AuditTraceResponse)
async def get_audit_trace(audit_id: UUID, db: AsyncSession = Depends(get_db)):
    """Return evidence, normalized context, policy result, and audit lifecycle."""
    return await _get_audit(audit_id, db)

