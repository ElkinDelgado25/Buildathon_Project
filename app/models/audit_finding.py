"""Association between an audit run, a raw finding, and policy evidence."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AuditFinding(Base):
    """Normalized finding evaluated by a deterministic security policy."""

    __tablename__ = "audit_findings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    audit_run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("audit_runs.id"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("findings.id"), nullable=False
    )
    security_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(), ForeignKey("security_rules.id"), nullable=True
    )
    normalized_payload: Mapped[dict] = mapped_column(
        JSON, nullable=False, comment="Common SonarQube/ZAP finding shape"
    )
    policy_action: Mapped[str] = mapped_column(
        String(20), nullable=False, comment="'allow' | 'review' | 'block'"
    )
    policy_reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    audit_run = relationship("AuditRun", back_populates="audit_findings")
    finding = relationship("Finding", lazy="selectin")
    security_rule = relationship("SecurityRule", back_populates="audit_findings")

