"""Pydantic schemas for planned and evidence-backed security audits."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.finding import FindingCreate, FindingResponse


class AuditPlanCreate(BaseModel):
    """Request a bounded audit before any scanner action is executed."""

    target: str = Field(..., min_length=1, max_length=500)
    scan_type: Literal["sast", "dast", "full"]
    dast_authorized: bool = False


class AuditRunResponse(BaseModel):
    id: UUID
    target: str
    scan_type: str
    status: str
    dast_authorized: bool
    decision: str | None = None
    policy_reason: str | None = None
    created_at: datetime
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}


class AuditFindingCreate(FindingCreate):
    """Raw scanner evidence attached to one audit run."""

    security_rule_id: UUID | None = None


class AuditFindingResponse(BaseModel):
    id: UUID
    audit_run_id: UUID
    finding: FindingResponse
    normalized_payload: dict
    policy_action: str
    policy_reason: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditTraceResponse(AuditRunResponse):
    audit_findings: list[AuditFindingResponse]

