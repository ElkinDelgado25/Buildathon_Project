"""Pydantic schemas for audit log entries."""

from datetime import datetime
from typing import Optional, Literal
from uuid import UUID

from pydantic import BaseModel, Field


class AuditLogCreate(BaseModel):
    """Schema for submitting a human review."""
    decision_id: UUID = Field(..., description="ID of the decision being reviewed")
    reviewed_by: str = Field(..., description="Name or ID of the analyst", max_length=100)
    review_comment: Optional[str] = Field(None, description="Analyst's feedback")
    review_verdict: Literal["agree", "disagree", "escalate"] = Field(
        ..., description="Analyst's verdict on the AI decision"
    )


class AuditLogResponse(BaseModel):
    """Schema returned when querying audit logs."""
    id: UUID
    decision_id: UUID
    reviewed_by: Optional[str] = None
    review_comment: Optional[str] = None
    review_verdict: Optional[str] = None
    reviewed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
