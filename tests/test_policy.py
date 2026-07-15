"""Unit tests for scanner normalization and deterministic audit policy."""

import unittest

from app.services.normalization_service import normalize_finding
from app.services.policy_service import evaluate_finding


class PolicyTests(unittest.TestCase):
    def test_critical_sonarqube_sql_injection_blocks_audit(self) -> None:
        normalized = normalize_finding(
            "sonarqube",
            {
                "rule": "python:S5131",
                "severity": "CRITICAL",
                "message": "SQL query built from user input",
                "tags": ["sql-injection", "cwe-89"],
            },
        )

        self.assertEqual(normalized["cwe_id"], "89")
        self.assertEqual(normalized["owasp_category"], "A03:2021 Injection")
        self.assertEqual(evaluate_finding(normalized).action, "block")

    def test_low_confidence_zap_alert_requires_review(self) -> None:
        normalized = normalize_finding(
            "zap",
            {
                "alertRef": "40012",
                "alert": "Cross Site Scripting",
                "riskcode": "1",
                "confidence": "0",
                "cweid": "79",
            },
        )

        self.assertEqual(normalized["owasp_category"], "A03:2021 Injection")
        self.assertEqual(evaluate_finding(normalized).action, "review")


if __name__ == "__main__":
    unittest.main()
