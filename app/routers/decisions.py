"""
Decisions router — the traceability/audit view.
Provides endpoints to review AI decisions and their audit summaries.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Decision
from app.schemas.decision import DecisionResponse, DecisionDetail, TokenUsageSummary
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
    "/usage",
    response_model=TokenUsageSummary,
    summary="Get cumulative OpenAI token usage",
)
async def get_token_usage(db: AsyncSession = Depends(get_db)):
    """Return tokens reported by OpenAI for all persisted LLM decisions."""
    stmt = select(
        func.count(Decision.id),
        func.coalesce(func.sum(Decision.prompt_tokens), 0),
        func.coalesce(func.sum(Decision.completion_tokens), 0),
        func.coalesce(func.sum(Decision.total_tokens), 0),
    )
    result = await db.execute(stmt)
    count, prompt_tokens, completion_tokens, total_tokens = result.one()
    return TokenUsageSummary(
        analyzed_decisions=int(count),
        prompt_tokens=int(prompt_tokens),
        completion_tokens=int(completion_tokens),
        total_tokens=int(total_tokens),
    )


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
