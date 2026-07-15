"""Audit run model — tracks a planned or executed DevSecOps audit."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AuditRun(Base):
    """A bounded SAST, DAST, or combined audit authorized by an analyst."""

    __tablename__ = "audit_runs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    target: Mapped[str] = mapped_column(
        String(500), nullable=False, comment="Authorized repository, image, or URL"
    )
    scan_type: Mapped[str] = mapped_column(
        String(20), nullable=False, comment="'sast' | 'dast' | 'full'"
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="planned", comment="Audit lifecycle state"
    )
    dast_authorized: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, comment="Explicit DAST authorization"
    )
    decision: Mapped[str | None] = mapped_column(
        String(20), nullable=True, comment="'allow' | 'review' | 'block'"
    )
    policy_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Deterministic policy explanation"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    audit_findings = relationship(
        "AuditFinding", back_populates="audit_run", lazy="selectin"
    )

