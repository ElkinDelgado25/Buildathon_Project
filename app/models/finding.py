"""Finding model — stores raw vulnerability data from sensors."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime, JSON, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), primary_key=True, default=uuid.uuid4
    )
    source: Mapped[str] = mapped_column(
        String(20), nullable=False, comment="'sonarqube' | 'zap'"
    )
    raw_payload: Mapped[dict] = mapped_column(
        JSON, nullable=False, comment="Original finding without modifications"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    decisions = relationship("Decision", back_populates="finding", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, source={self.source})>"
