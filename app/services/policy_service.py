"""Deterministic security policy evaluation before optional LLM enrichment."""

from dataclasses import dataclass
from typing import Literal


PolicyAction = Literal["allow", "review", "block"]

_ACTION_PRIORITY = {"allow": 0, "review": 1, "block": 2}


@dataclass(frozen=True)
class PolicyResult:
    action: PolicyAction
    reason: str


def evaluate_finding(normalized: dict) -> PolicyResult:
    """Apply explainable rules that do not depend on model output."""
    severity = normalized.get("severity", "medium")
    confidence = normalized.get("confidence", "low")
    title = normalized.get("title", "security finding")

    if severity == "critical" and confidence in {"high", "confirmed"}:
        return PolicyResult("block", f"Critical, high-confidence finding: {title}.")
    if severity == "critical":
        return PolicyResult("review", f"Critical finding requires human validation: {title}.")
    if severity == "high":
        return PolicyResult("review", f"High-severity finding requires human review: {title}.")
    if confidence == "low":
        return PolicyResult("review", f"Low-confidence finding requires analyst review: {title}.")
    return PolicyResult("allow", f"No blocking policy matched for: {title}.")


def aggregate_actions(results: list[PolicyResult]) -> PolicyResult:
    """Return the strictest result so an audit cannot downgrade a serious finding."""
    if not results:
        return PolicyResult("allow", "No findings were attached to this audit.")
    strictest = max(results, key=lambda result: _ACTION_PRIORITY[result.action])
    return strictest

