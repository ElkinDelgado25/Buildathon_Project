"""
Audit router — human review of AI decisions.
Enables analysts to formally agree, disagree, or escalate AI decisions.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import AuditLog
from app.schemas.audit_log import AuditLogCreate, AuditLogResponse
from app.services.audit_service import AuditService, DecisionNotFoundError

router = APIRouter(prefix="/audit", tags=["Audit & Human Review"])
audit_service = AuditService()


@router.post(
    "/review",
    response_model=AuditLogResponse,
    summary="Submit a human review of an AI decision",
    description="Analysts use this endpoint to record their review of an AI decision.",
)
async def create_review(
    review: AuditLogCreate,
    db: AsyncSession = Depends(get_db),
):
    """Submit a human review for an AI decision."""
    try:
        return await audit_service.create_review(review, db)
    except DecisionNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/reviews",
    response_model=list[AuditLogResponse],
    summary="List all audit reviews",
)
async def list_reviews(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List all human reviews with pagination."""
    stmt = (
        select(AuditLog)
        .order_by(AuditLog.reviewed_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get(
    "/decision/{decision_id}/reviews",
    response_model=list[AuditLogResponse],
    summary="Get reviews for a specific decision",
)
async def get_decision_reviews(
    decision_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get all human reviews for a specific AI decision."""
    stmt = (
        select(AuditLog)
        .where(AuditLog.decision_id == decision_id)
        .order_by(AuditLog.reviewed_at.desc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())
