"""Security rule model — cached metadata from SonarQube or OWASP ZAP."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, JSON, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class SecurityRule(Base):
    """A scanner rule normalized for policy evaluation and auditor context."""

    __tablename__ = "security_rules"
    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_rule_source_external_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(30), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(80), nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_rule: Mapped[dict] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    audit_findings = relationship(
        "AuditFinding", back_populates="security_rule", lazy="selectin"
    )

