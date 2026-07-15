"""Pydantic schemas for scanner rules cached by the audit service."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class SecurityRuleCreate(BaseModel):
    source: Literal["sonarqube", "zap"]
    external_id: str = Field(..., min_length=1, max_length=200)
    title: str = Field(..., min_length=1, max_length=500)
    description: str | None = None
    severity: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    remediation: str | None = None
    raw_rule: dict


class SecurityRuleResponse(SecurityRuleCreate):
    id: UUID
    updated_at: datetime

    model_config = {"from_attributes": True}

