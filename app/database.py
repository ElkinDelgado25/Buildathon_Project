"""
Async database engine and session management.
Uses SQLAlchemy 2.0 async API with the asyncpg PostgreSQL driver.
"""

import os

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from app.config import settings

# ── Engine ────────────────────────────────────────────────────
_database_url = settings.DATABASE_URL
# Render provides a standard PostgreSQL URL. SQLAlchemy's async engine needs
# the asyncpg dialect prefix used by this application.
if _database_url.startswith("postgres://"):
    _database_url = _database_url.replace(
        "postgres://", "postgresql+asyncpg://", 1
    )
elif _database_url.startswith("postgresql://"):
    _database_url = _database_url.replace(
        "postgresql://", "postgresql+asyncpg://", 1
    )

engine_options = {
    "echo": settings.APP_ENV == "development",
    "pool_pre_ping": True,
}

# Vercel Functions scale horizontally. Reusing a local SQLAlchemy pool from
# each Function instance can exhaust Supabase's transaction pooler, so every
# request gets a short-lived connection in that environment.
if os.getenv("VERCEL") == "1":
    engine_options["poolclass"] = NullPool
else:
    engine_options["pool_size"] = 10
    engine_options["max_overflow"] = 20

engine = create_async_engine(_database_url, **engine_options)

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
