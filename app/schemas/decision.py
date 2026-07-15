"""Pydantic schemas for decisions."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class DecisionResponse(BaseModel):
    """Compact decision summary."""
    id: UUID
    finding_id: UUID
    llm_model: str
    final_decision: str
    severity_assessed: Optional[str] = None
    confidence_score: Optional[float] = None
    suggested_action: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class DecisionDetail(BaseModel):
    """
    Full decision with Chain of Thought — the core traceability view.
    This is what an auditor sees when reviewing AI decisions.
    """
    id: UUID
    finding_id: UUID
    llm_model: str
    prompt_used: str
    chain_of_thought: str
    final_decision: str
    severity_assessed: Optional[str] = None
    confidence_score: Optional[float] = None
    suggested_action: Optional[str] = None
    created_at: datetime

    # Nested original finding for full context
    finding: Optional["FindingInDecision"] = None

    model_config = {"from_attributes": True}


class FindingInDecision(BaseModel):
    """Embedded finding data inside a decision detail view."""
    id: UUID
    source: str
    raw_payload: dict
    created_at: datetime

    model_config = {"from_attributes": True}


# Rebuild to resolve forward reference
DecisionDetail.model_rebuild()
