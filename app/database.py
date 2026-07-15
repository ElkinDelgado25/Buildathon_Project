"""
Async database engine and session management.
Uses SQLAlchemy 2.0 async API with asyncpg driver (PostgreSQL)
or aiosqlite (SQLite for local development).
"""

import json

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

# ── Engine ────────────────────────────────────────────────────
# SQLite doesn't support pool_size/max_overflow, so conditionally apply them
_is_sqlite = settings.DATABASE_URL.startswith("sqlite")

_engine_kwargs = {
    "echo": settings.APP_ENV == "development",
}

if not _is_sqlite:
    _engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
    })
else:
    # SQLite needs json_serializer for dict columns
    _engine_kwargs["json_serializer"] = json.dumps
    _engine_kwargs["json_deserializer"] = json.loads

engine = create_async_engine(
    settings.DATABASE_URL,
    **_engine_kwargs,
)

# ── Session factory ──────────────────────────────────────────
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Base model ───────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── Dependency for FastAPI ───────────────────────────────────
async def get_db() -> AsyncSession:
    """Yield a database session per request, with automatic cleanup."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
