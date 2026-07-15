"""Reusable audit and human-review use cases for HTTP and command adapters."""

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import AuditFinding, AuditLog, AuditRun, Decision, Finding, SecurityRule
from app.schemas.audit_log import AuditLogCreate
from app.schemas.audit_run import AuditFindingCreate, AuditPlanCreate
from app.services.normalization_service import normalize_finding
from app.services.policy_service import PolicyResult, aggregate_actions, evaluate_finding


class AuditNotFoundError(ValueError):
    """Raised when an audit does not exist."""


class SecurityRuleNotFoundError(ValueError):
    """Raised when a referenced scanner rule does not exist."""


class DecisionNotFoundError(ValueError):
    """Raised when a referenced AI decision does not exist."""


class AuditService:
    """Coordinates audit plans, evidence, policies, and human reviews."""

    async def get_audit(
        self, audit_id: UUID, db: AsyncSession
    ) -> AuditRun | None:
        result = await db.execute(
            select(AuditRun)
            .options(
                selectinload(AuditRun.audit_findings).selectinload(
                    AuditFinding.finding
                )
            )
            .where(AuditRun.id == audit_id)
        )
        return result.scalar_one_or_none()

    async def create_plan(
        self, plan: AuditPlanCreate, db: AsyncSession
    ) -> AuditRun:
        if plan.scan_type in {"dast", "full"} and not plan.dast_authorized:
            raise ValueError("DAST requires explicit authorization for the target.")
        audit = AuditRun(**plan.model_dump())
        db.add(audit)
        await db.flush()
        return audit

    async def attach_finding(
        self,
        audit_id: UUID,
        incoming: AuditFindingCreate,
        db: AsyncSession,
    ) -> AuditFinding:
        audit = await self.get_audit(audit_id, db)
        if audit is None:
            raise AuditNotFoundError("Audit not found")

        security_rule = None
        if incoming.security_rule_id:
            security_rule = await db.get(SecurityRule, incoming.security_rule_id)
            if security_rule is None:
                raise SecurityRuleNotFoundError("Security rule not found")

        finding = Finding(source=incoming.source, raw_payload=incoming.raw_payload)
        db.add(finding)
        await db.flush()

        normalized = normalize_finding(incoming.source, incoming.raw_payload)
        policy = evaluate_finding(normalized)
        audit_finding = AuditFinding(
            audit_run_id=audit.id,
            finding_id=finding.id,
            security_rule_id=security_rule.id if security_rule else None,
            normalized_payload=normalized,
            policy_action=policy.action,
            policy_reason=policy.reason,
        )
        audit_finding.finding = finding
        db.add(audit_finding)
        audit.audit_findings.append(audit_finding)
        audit.status = "running"
        await db.flush()
        self._update_audit_decision(audit)
        await db.flush()
        return audit_finding

    async def create_review(
        self, review: AuditLogCreate, db: AsyncSession
    ) -> AuditLog:
        decision = await db.get(Decision, review.decision_id)
        if decision is None:
            raise DecisionNotFoundError("Decision not found")

        audit_entry = AuditLog(
            decision_id=review.decision_id,
            reviewed_by=review.reviewed_by,
            review_comment=review.review_comment,
            review_verdict=review.review_verdict,
            reviewed_at=datetime.now(timezone.utc),
        )
        db.add(audit_entry)
        await db.flush()
        return audit_entry

    @staticmethod
    def _update_audit_decision(audit: AuditRun) -> None:
        results = [
            PolicyResult(item.policy_action, item.policy_reason)
            for item in audit.audit_findings
        ]
        outcome = aggregate_actions(results)
        audit.decision = outcome.action
        audit.policy_reason = outcome.reason
        audit.status = "completed"
        audit.completed_at = datetime.now(timezone.utc)
