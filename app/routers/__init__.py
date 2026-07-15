"""API Routers package."""

from app.routers.findings import router as findings_router
from app.routers.decisions import router as decisions_router
from app.routers.audit import router as audit_router
from app.routers.audits import router as audits_router
from app.routers.rules import router as rules_router
from app.routers.commands import router as commands_router

__all__ = [
    "findings_router",
    "decisions_router",
    "audit_router",
    "audits_router",
    "rules_router",
    "commands_router",
]
