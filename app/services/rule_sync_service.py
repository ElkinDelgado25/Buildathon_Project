"""Convert SonarQube and ZAP rule payloads into the local rule catalog shape."""

import re

from app.schemas.security_rule import SecurityRuleCreate


def _find_cwe(values: object) -> str | None:
    if not isinstance(values, list):
        return None
    for value in values:
        match = re.search(r"cwe[: -]?(\d+)", str(value), flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def sonar_rule_to_schema(rule: dict) -> SecurityRuleCreate:
    standards = rule.get("securityStandards", [])
    owasp = next(
        (
            str(standard).replace("owaspTop10:", "A").upper()
            for standard in standards
            if str(standard).lower().startswith("owasptop10:")
        ),
        None,
    )
    return SecurityRuleCreate(
        source="sonarqube",
        external_id=str(rule["key"]),
        title=rule.get("name", rule["key"]),
        description=rule.get("htmlDesc") or rule.get("mdDesc"),
        severity=rule.get("severity", "").lower() or None,
        cwe_id=_find_cwe(standards),
        owasp_category=owasp,
        remediation=rule.get("remediationFunction"),
        raw_rule=rule,
    )


def zap_rule_to_schema(rule: dict) -> SecurityRuleCreate:
    rule_id = str(rule.get("id") or rule.get("alertRef") or rule.get("name"))
    return SecurityRuleCreate(
        source="zap",
        external_id=rule_id,
        title=rule.get("name", f"ZAP scanner {rule_id}"),
        description=rule.get("description"),
        severity=None,
        cwe_id=None,
        owasp_category=None,
        remediation=None,
        raw_rule=rule,
    )

