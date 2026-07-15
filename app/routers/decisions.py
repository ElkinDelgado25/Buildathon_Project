"""
Decisions router — the traceability/audit view.
Provides endpoints to review AI decisions and their audit summaries.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.decision import DecisionResponse, DecisionDetail
from app.services.analysis_service import AnalysisService

router = APIRouter(prefix="/decisions", tags=["Decisions & Traceability"])

analysis_service = AnalysisService()


@router.get(
    "/",
    response_model=list[DecisionResponse],
    summary="List all AI decisions",
    description="Paginated list of all decisions, newest first. Use this for the audit dashboard.",
)
async def list_decisions(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List all decisions with pagination."""
    decisions = await analysis_service.list_decisions(db, limit=limit, offset=offset)
    return decisions


@router.get(
    "/{decision_id}",
    response_model=DecisionDetail,
    summary="Get full decision detail and audit summary",
    description=(
        "Returns the complete decision including its evidence-based audit summary, "
        "the exact prompt used, and the original finding. This is the core "
        "traceability endpoint for auditors."
    ),
)
async def get_decision_detail(
    decision_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    The key traceability endpoint.
    Returns: finding → prompt → audit summary → decision → suggested action.
    """
    decision = await analysis_service.get_decision_detail(decision_id, db)

    if not decision:
        raise HTTPException(status_code=404, detail="Decision not found")

    return decision
