"""
OWASP ZAP sensor — fetches DAST findings from ZAP's API or JSON reports.

NOTE: This is a Phase 3 integration. Skeleton ready for connection
once the core analysis pipeline is validated.
"""

import json
import logging
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class ZAPClient:
    """Client for OWASP ZAP's API and report ingestion."""

    def __init__(self, base_url: str = "http://localhost:8080", api_key: str = ""):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    async def fetch_alerts(
        self,
        base_url_filter: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> list[dict]:
        """
        Fetch alerts from ZAP's running instance.

        Args:
            base_url_filter: Only return alerts for this base URL
            risk_level: Filter by risk level (Informational, Low, Medium, High)

        Returns:
            List of raw alert dicts from ZAP
        """
        params = {"apikey": self.api_key}
        if base_url_filter:
            params["baseurl"] = base_url_filter

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{self.base_url}/JSON/alert/view/alerts/",
                params=params,
            )
            response.raise_for_status()
            data = response.json()
            alerts = data.get("alerts", [])

            if risk_level:
                risk_map = {
                    "Informational": "0",
                    "Low": "1",
                    "Medium": "2",
                    "High": "3",
                }
                alerts = [
                    a for a in alerts
                    if a.get("riskcode") == risk_map.get(risk_level, risk_level)
                ]

            logger.info(f"Fetched {len(alerts)} alerts from ZAP")
            return alerts

    async def fetch_rules(self) -> list[dict]:
        """Download active and passive ZAP scanner-rule metadata."""
        params = {"apikey": self.api_key}
        async with httpx.AsyncClient(timeout=30.0) as client:
            active_response = await client.get(
                f"{self.base_url}/JSON/ascan/view/scanners/", params=params
            )
            passive_response = await client.get(
                f"{self.base_url}/JSON/pscan/view/scanners/", params=params
            )
            active_response.raise_for_status()
            passive_response.raise_for_status()

        active_rules = active_response.json().get("scanners", [])
        passive_rules = passive_response.json().get("scanners", [])
        rules = [
            {**rule, "scannerType": "active"}
            for rule in active_rules
        ] + [
            {**rule, "scannerType": "passive"}
            for rule in passive_rules
        ]
        logger.info("Fetched %s scanner rules from ZAP", len(rules))
        return rules

    @staticmethod
    def parse_json_report(report_path: str) -> list[dict]:
        """
        Parse a ZAP JSON report file exported from the tool.

        Args:
            report_path: Path to the ZAP JSON report file

        Returns:
            List of alert dicts extracted from the report
        """
        path = Path(report_path)
        if not path.exists():
            raise FileNotFoundError(f"ZAP report not found: {report_path}")

        with open(path) as f:
            report = json.load(f)

        # ZAP JSON reports have alerts nested under site > alerts
        alerts = []
        for site in report.get("site", []):
            for alert in site.get("alerts", []):
                alerts.append(alert)

        logger.info(f"Parsed {len(alerts)} alerts from ZAP report: {report_path}")
        return alerts
