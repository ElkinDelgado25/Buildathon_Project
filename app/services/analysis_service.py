"""
Analysis Service — orchestrates the full analysis pipeline.

1. Persist the raw finding
2. Send to LLM for analysis
3. Persist the decision with Chain of Thought
4. Return the complete result
"""

import logging
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Finding, Decision
from app.services.llm_service import LLMService

logger = logging.getLogger(__name__)


class AnalysisService:
    """Orchestrates finding ingestion → LLM analysis → decision persistence."""

    def __init__(self):
        self.llm = LLMService()

    async def analyze(self, source: str, raw_payload: dict, db: AsyncSession) -> Decision:
        """
        Full analysis pipeline:
        1. Store the raw finding (immutable record)
        2. Call the LLM for structured analysis
        3. Store the decision with full Chain of Thought
        """
        # ── Step 1: Persist the raw finding ──────────────────
        finding = Finding(source=source, raw_payload=raw_payload)
        db.add(finding)
        await db.flush()  # Get the UUID without committing

        logger.info(f"Finding persisted: {finding.id} (source={source})")

        # ── Step 2: LLM Analysis ────────────────────────────
        llm_result = await self.llm.analyze_finding(source, raw_payload)

        logger.info(
            f"LLM decision: {llm_result.final_decision} "
            f"(confidence={llm_result.confidence_score}, model={llm_result.model_used})"
        )

        # ── Step 3: Persist the decision ────────────────────
        decision = Decision(
            finding_id=finding.id,
            llm_model=llm_result.model_used,
            prompt_used=llm_result.prompt_used,
            chain_of_thought=llm_result.chain_of_thought,
            final_decision=llm_result.final_decision,
            severity_assessed=llm_result.severity_assessed,
            confidence_score=llm_result.confidence_score,
            suggested_action=llm_result.suggested_action,
        )
        db.add(decision)
        await db.flush()

        logger.info(f"Decision persisted: {decision.id}")

        return decision

    async def get_decision_detail(self, decision_id: UUID, db: AsyncSession) -> Decision | None:
        """Fetch a decision with its full Chain of Thought and original finding."""
        stmt = (
            select(Decision)
            .options(selectinload(Decision.finding))
            .where(Decision.id == decision_id)
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_decisions(
        self, db: AsyncSession, limit: int = 50, offset: int = 0
    ) -> list[Decision]:
        """List decisions with pagination, newest first."""
        stmt = (
            select(Decision)
            .options(selectinload(Decision.finding))
            .order_by(Decision.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())

    async def get_finding_decisions(
        self, finding_id: UUID, db: AsyncSession
    ) -> list[Decision]:
        """Get all decisions for a specific finding (supports re-analysis)."""
        stmt = (
            select(Decision)
            .where(Decision.finding_id == finding_id)
            .order_by(Decision.created_at.desc())
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())
