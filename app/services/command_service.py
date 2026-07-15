"""Safe dispatcher for the fixed Web CLI command catalog."""

import shlex
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog, Decision, Finding
from app.schemas.audit_log import AuditLogCreate, AuditLogResponse
from app.schemas.audit_run import AuditPlanCreate, AuditRunResponse
from app.schemas.command import CommandRequest, CommandResponse
from app.schemas.decision import DecisionDetail, DecisionResponse
from app.schemas.finding import FindingResponse
from app.services.analysis_service import AnalysisService
from app.services.audit_service import AuditService, DecisionNotFoundError


OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

HELP_TEXT = [
    "/help",
    "/status",
    "/dashboard",
    "/owasp audit A01 ... A10  (requires target; instruction is optional)",
    "/findings list",
    "/decisions list",
    "/decisions show <decision-id>",
    "/review <decision-id> <agree|disagree|escalate>",
]


class CommandValidationError(ValueError):
    """Raised for unsupported or malformed Web CLI commands."""


class CommandDispatcher:
    """Interpret only documented commands and delegate to existing use cases."""

    def __init__(self) -> None:
        self.analysis = AnalysisService()
        self.audits = AuditService()

    async def dispatch(
        self, request: CommandRequest, db: AsyncSession
    ) -> CommandResponse:
        parts = self._parse(request.command)
        command = " ".join(parts)

        if parts == ["help"]:
            return CommandResponse(
                command="/help",
                result_type="help",
                status="ok",
                message="Available CyberSec Agent commands.",
                data={"commands": HELP_TEXT},
                suggestions=["/status", "/owasp audit A03"],
            )
        if parts in (["status"], ["dashboard"]):
            return await self._system_status(command, db)
        if parts == ["findings", "list"]:
            return await self._list_findings(command, db)
        if parts == ["decisions", "list"]:
            return await self._list_decisions(command, db)
        if len(parts) == 3 and parts[:2] == ["decisions", "show"]:
            return await self._show_decision(command, parts[2], db)
        if len(parts) == 3 and parts[:2] == ["owasp", "audit"]:
            return await self._create_owasp_audit(command, parts[2], request, db)
        if len(parts) == 3 and parts[0] == "review":
            return await self._create_review(command, parts[1], parts[2], request, db)

        raise CommandValidationError(
            "Unknown or incomplete command. Use /help to see the supported catalog."
        )

    @staticmethod
    def _parse(raw_command: str) -> list[str]:
        try:
            parts = shlex.split(raw_command.strip())
        except ValueError as exc:
            raise CommandValidationError(f"Invalid command syntax: {exc}") from exc
        if not parts:
            raise CommandValidationError("A command is required.")
        if parts[0].startswith("/"):
            parts[0] = parts[0][1:]
        return [part.lower() if index in {0, 1, 2} else part for index, part in enumerate(parts)]

    async def _system_status(
        self, command: str, db: AsyncSession
    ) -> CommandResponse:
        await db.execute(text("SELECT 1"))
        findings = await db.scalar(select(func.count(Finding.id)))
        decisions = await db.scalar(select(func.count(Decision.id)))
        reviews = await db.scalar(select(func.count(AuditLog.id)))
        return CommandResponse(
            command=f"/{command}",
            result_type="dashboard",
            status="healthy",
            message="API and database are available.",
            data={
                "findings": findings or 0,
                "decisions": decisions or 0,
                "reviews": reviews or 0,
            },
            suggestions=["/findings list", "/decisions list", "/owasp audit A03"],
        )

    async def _list_findings(
        self, command: str, db: AsyncSession
    ) -> CommandResponse:
        result = await db.execute(
            select(Finding).order_by(Finding.created_at.desc()).limit(50)
        )
        findings = [
            FindingResponse.model_validate(item).model_dump(mode="json")
            for item in result.scalars().all()
        ]
        return CommandResponse(
            command=f"/{command}",
            result_type="findings",
            status="ok",
            message=f"{len(findings)} finding(s) found.",
            data=findings,
            suggestions=["/decisions list", "/owasp audit A03"],
        )

    async def _list_decisions(
        self, command: str, db: AsyncSession
    ) -> CommandResponse:
        decisions = await self.analysis.list_decisions(db, limit=50)
        data = [
            DecisionResponse.model_validate(item).model_dump(mode="json")
            for item in decisions
        ]
        return CommandResponse(
            command=f"/{command}",
            result_type="decisions",
            status="ok",
            message=f"{len(data)} decision(s) found.",
            data=data,
            suggestions=["/decisions show <decision-id>"],
        )

    async def _show_decision(
        self, command: str, decision_id: str, db: AsyncSession
    ) -> CommandResponse:
        try:
            parsed_id = UUID(decision_id)
        except ValueError as exc:
            raise CommandValidationError("Decision ID must be a UUID.") from exc
        decision = await self.analysis.get_decision_detail(parsed_id, db)
        if decision is None:
            raise CommandValidationError("Decision not found.")
        return CommandResponse(
            command=f"/{command}",
            result_type="decision",
            status="ok",
            message="Decision trace loaded.",
            data=DecisionDetail.model_validate(decision).model_dump(mode="json"),
            suggestions=[f"/review {decision_id} agree"],
        )

    async def _create_owasp_audit(
        self,
        command: str,
        category: str,
        request: CommandRequest,
        db: AsyncSession,
    ) -> CommandResponse:
        category = category.upper()
        if category not in OWASP_CATEGORIES:
            raise CommandValidationError("OWASP category must be A01 through A10.")
        if not request.target:
            raise CommandValidationError(
                "An authorized target is required for an OWASP audit."
            )
        plan = AuditPlanCreate(
            target=request.target,
            scan_type="sast",
            dast_authorized=False,
            owasp_category=category,
            instruction=request.instruction,
        )
        audit = await self.audits.create_plan(plan, db)
        return CommandResponse(
            command=f"/owasp audit {category}",
            result_type="owasp_audit",
            status="awaiting_evidence",
            message=(
                f"{category} {OWASP_CATEGORIES[category]} audit recorded. "
                "No scanner was launched; attach authorized scanner evidence next."
            ),
            data=AuditRunResponse.model_validate(audit).model_dump(mode="json"),
            suggestions=[
                "Attach a SonarQube or ZAP finding through the audit evidence API.",
                f"/audits trace {audit.id}",
            ],
        )

    async def _create_review(
        self,
        command: str,
        decision_id: str,
        verdict: str,
        request: CommandRequest,
        db: AsyncSession,
    ) -> CommandResponse:
        try:
            parsed_id = UUID(decision_id)
        except ValueError as exc:
            raise CommandValidationError("Decision ID must be a UUID.") from exc
        if verdict not in {"agree", "disagree", "escalate"}:
            raise CommandValidationError(
                "Review verdict must be agree, disagree, or escalate."
            )
        if not request.reviewed_by:
            raise CommandValidationError("A reviewer is required for /review.")
        try:
            review = await self.audits.create_review(
                AuditLogCreate(
                    decision_id=parsed_id,
                    reviewed_by=request.reviewed_by,
                    review_verdict=verdict,
                    review_comment=request.review_comment,
                ),
                db,
            )
        except DecisionNotFoundError as exc:
            raise CommandValidationError(str(exc)) from exc
        return CommandResponse(
            command=f"/{command}",
            result_type="review",
            status="ok",
            message="Human review recorded.",
            data=AuditLogResponse.model_validate(review).model_dump(mode="json"),
            suggestions=["/decisions list"],
        )
