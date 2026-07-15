"""Decision model — stores LLM analysis results with an auditable summary."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Text, Numeric, DateTime, ForeignKey, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Decision(Base):
    __tablename__ = "decisions"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), primary_key=True, default=uuid.uuid4
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("findings.id"), nullable=False
    )
    llm_model: Mapped[str] = mapped_column(
        String(100), nullable=False, comment="e.g. 'openai/gpt-4.1-mini'"
    )
    prompt_used: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Exact prompt sent to the LLM for reproducibility"
    )
    analysis_summary: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Concise, evidence-based audit rationale"
    )
    final_decision: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        comment="'amenaza_confirmada' | 'falso_positivo' | 'requiere_revision_humana'",
    )
    severity_assessed: Mapped[str | None] = mapped_column(
        String(20), nullable=True, comment="Reassessed severity by the LLM"
    )
    confidence_score: Mapped[float | None] = mapped_column(
        Numeric(3, 2), nullable=True, comment="0.00 to 1.00"
    )
    suggested_action: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Recommended remediation action"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    finding = relationship("Finding", back_populates="decisions")
    audit_logs = relationship("AuditLog", back_populates="decision", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Decision(id={self.id}, verdict={self.final_decision})>"
