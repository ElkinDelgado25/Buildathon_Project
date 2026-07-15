"""
Findings router — handles finding ingestion and the core /analyze-finding endpoint.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import Finding
from app.schemas.finding import SimulatedFinding, FindingResponse
from app.schemas.decision import DecisionDetail
from app.services.analysis_service import AnalysisService

router = APIRouter(prefix="/findings", tags=["Findings & Analysis"])

analysis_service = AnalysisService()


@router.post(
    "/analyze",
    response_model=DecisionDetail,
    summary="Analyze a security finding",
    description=(
        "Receives a security finding (real or simulated), sends it to the LLM "
        "for Chain of Thought analysis, and persists both the raw finding and "
        "the complete decision with reasoning. This is the core endpoint of the agent."
    ),
)
async def analyze_finding(
    finding: SimulatedFinding,
    db: AsyncSession = Depends(get_db),
):
    """
    Core endpoint — the 'brain' of the cybersecurity agent.

    Flow:
    1. Receives a finding payload (from a sensor or simulated)
    2. Persists the raw finding immutably
    3. Sends to LLM with structured prompt requesting Chain of Thought
    4. Persists the decision with full reasoning
    5. Returns the complete decision for immediate review
    """
    try:
        decision = await analysis_service.analyze(
            source=finding.source,
            raw_payload=finding.raw_payload,
            db=db,
        )

        # Reload with relationships for the response
        detail = await analysis_service.get_decision_detail(decision.id, db)
        return detail

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}",
        )


@router.get(
    "/",
    response_model=list[FindingResponse],
    summary="List all findings",
)
async def list_findings(
    limit: int = 50,
    offset: int = 0,
    source: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List findings with optional filtering by source."""
    stmt = select(Finding).order_by(Finding.created_at.desc())

    if source:
        stmt = stmt.where(Finding.source == source)

    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Get a specific finding",
)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve a specific finding by ID."""
    from uuid import UUID

    try:
        uid = UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    stmt = select(Finding).where(Finding.id == uid)
    result = await db.execute(stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return finding
