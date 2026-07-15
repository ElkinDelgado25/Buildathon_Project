"""AuditLog model — tracks human reviews of AI decisions."""

import uuid
from datetime import datetime

from sqlalchemy import String, Text, DateTime, ForeignKey, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), primary_key=True, default=uuid.uuid4
    )
    decision_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("decisions.id"), nullable=False
    )
    reviewed_by: Mapped[str | None] = mapped_column(
        String(100), nullable=True, comment="Human analyst who reviewed"
    )
    review_comment: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Analyst's feedback or override reason"
    )
    review_verdict: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
        comment="Analyst override: 'agree' | 'disagree' | 'escalate'",
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    decision = relationship("Decision", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, reviewed_by={self.reviewed_by})>"
