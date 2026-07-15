"""
Cybersecurity Agent — FastAPI Application Entry Point

An intelligent vulnerability analysis agent that converts raw security
findings into traceable, auditable decisions using LLM analysis.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine, Base
from app.routers import findings_router, decisions_router, audit_router

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── Lifespan (startup/shutdown) ──────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables on startup (dev convenience). Use Alembic in production."""
    logger.info("🚀 Starting Cybersecurity Agent...")
    logger.info(f"   Environment: {settings.APP_ENV}")
    logger.info(f"   LLM Provider: {settings.LLM_PROVIDER}")

    # Auto-create tables in development
    if settings.APP_ENV == "development":
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            logger.info("   ✅ Database tables created/verified")

    yield

    # Shutdown
    await engine.dispose()
    logger.info("👋 Cybersecurity Agent stopped.")


# ── FastAPI App ──────────────────────────────────────────────
app = FastAPI(
    title="🛡️ Cybersecurity Agent API",
    description=(
        "An intelligent agent that analyzes SAST/DAST security findings "
        "using OpenAI with evidence-based audit summaries. "
        "Every decision is auditable and reproducible."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ─────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ───────────────────────────────────────────────────
app.include_router(findings_router, prefix="/api/v1")
app.include_router(decisions_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")


@app.get("/", tags=["Health"])
async def root():
    """Health check and API info."""
    return {
        "status": "operational",
        "service": "Cybersecurity Agent",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "analyze_finding": "POST /api/v1/findings/analyze",
            "list_decisions": "GET /api/v1/decisions/",
            "decision_detail": "GET /api/v1/decisions/{id}",
            "submit_review": "POST /api/v1/audit/review",
        },
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Detailed health check including database connectivity."""
    from sqlalchemy import text

    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "llm_provider": settings.LLM_PROVIDER,
        "environment": settings.APP_ENV,
    }
