"""Normalize SAST and DAST payloads into a common auditor-facing format."""

from typing import Literal


OWASP_BY_CWE = {
    "22": "A01:2021 Broken Access Control",
    "79": "A03:2021 Injection",
    "89": "A03:2021 Injection",
    "200": "A01:2021 Broken Access Control",
    "287": "A07:2021 Identification and Authentication Failures",
    "327": "A02:2021 Cryptographic Failures",
    "352": "A01:2021 Broken Access Control",
    "502": "A08:2021 Software and Data Integrity Failures",
    "798": "A07:2021 Identification and Authentication Failures",
}

SONAR_SEVERITY = {
    "BLOCKER": "critical",
    "CRITICAL": "critical",
    "MAJOR": "high",
    "MINOR": "medium",
    "INFO": "info",
}

ZAP_SEVERITY = {"0": "info", "1": "low", "2": "medium", "3": "high"}
ZAP_CONFIDENCE = {"0": "low", "1": "medium", "2": "high", "3": "confirmed"}


def _cwe(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).upper().replace("CWE-", "").strip()
    return text if text.isdigit() else None


def _owasp(cwe_id: str | None, tags: object = None) -> str | None:
    if cwe_id in OWASP_BY_CWE:
        return OWASP_BY_CWE[cwe_id]
    if isinstance(tags, list):
        for tag in tags:
            if str(tag).lower().startswith("owasp-"):
                return str(tag).upper().replace("-", ":", 1)
    return None


def normalize_finding(source: Literal["sonarqube", "zap"], payload: dict) -> dict:
    """Return the minimum common shape used by policies and the audit trace."""
    if source == "sonarqube":
        tags = payload.get("tags", [])
        cwe_id = _cwe(payload.get("cwe") or payload.get("cweId"))
        if cwe_id is None and isinstance(tags, list):
            cwe_id = next((_cwe(tag) for tag in tags if _cwe(tag)), None)
        severity = SONAR_SEVERITY.get(str(payload.get("severity", "")).upper(), "medium")
        return {
            "source": source,
            "rule_id": payload.get("rule"),
            "title": payload.get("message", "SonarQube security finding"),
            "severity": severity,
            "confidence": "high",
            "cwe_id": cwe_id,
            "owasp_category": _owasp(cwe_id, tags),
            "location": {
                "component": payload.get("component"),
                "line": payload.get("line"),
            },
            "evidence": payload.get("message"),
            "remediation": payload.get("message"),
        }

    cwe_id = _cwe(payload.get("cweid"))
    risk_code = str(payload.get("riskcode", "0"))
    return {
        "source": source,
        "rule_id": payload.get("alertRef"),
        "title": payload.get("alert", "OWASP ZAP alert"),
        "severity": ZAP_SEVERITY.get(risk_code, "medium"),
        "confidence": ZAP_CONFIDENCE.get(str(payload.get("confidence", "0")), "low"),
        "cwe_id": cwe_id,
        "owasp_category": _owasp(cwe_id),
        "location": {
            "url": payload.get("url"),
            "method": payload.get("method"),
            "parameter": payload.get("param"),
        },
        "evidence": payload.get("evidence") or payload.get("description"),
        "remediation": payload.get("solution"),
    }

