"""
Audit router — human review of AI decisions.
Enables analysts to formally agree, disagree, or escalate AI decisions.
"""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import AuditLog, Decision
from app.schemas.audit_log import AuditLogCreate, AuditLogResponse

router = APIRouter(prefix="/audit", tags=["Audit & Human Review"])


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
    # Verify the decision exists
    stmt = select(Decision).where(Decision.id == review.decision_id)
    result = await db.execute(stmt)
    decision = result.scalar_one_or_none()

    if not decision:
        raise HTTPException(status_code=404, detail="Decision not found")

    audit_entry = AuditLog(
        decision_id=review.decision_id,
        reviewed_by=review.reviewed_by,
        review_comment=review.review_comment,
        review_verdict=review.review_verdict,
        reviewed_at=datetime.now(timezone.utc),
    )
    db.add(audit_entry)
    await db.flush()

    return audit_entry


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
