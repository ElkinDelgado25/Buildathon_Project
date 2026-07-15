"""Add OpenAI token usage columns to decisions.

Revision ID: 20260715_01
Revises:
Create Date: 2026-07-15
"""

from typing import Sequence, Union

from alembic import op


revision: str = "20260715_01"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    for column in ("prompt_tokens", "completion_tokens", "total_tokens"):
        op.execute(
            f"ALTER TABLE decisions ADD COLUMN IF NOT EXISTS {column} "
            "INTEGER NOT NULL DEFAULT 0"
        )


def downgrade() -> None:
    for column in ("total_tokens", "completion_tokens", "prompt_tokens"):
        op.execute(f"ALTER TABLE decisions DROP COLUMN IF EXISTS {column}")
