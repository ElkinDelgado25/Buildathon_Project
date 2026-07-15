"""
SonarQube sensor — fetches SAST findings from SonarQube's REST API.

NOTE: This is a Phase 3 integration. For now it serves as the skeleton
that will be connected once the core analysis pipeline is validated.
"""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class SonarQubeClient:
    """Client for SonarQube's Web API."""

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token

    async def fetch_issues(
        self,
        project_key: str,
        severities: Optional[str] = None,
        types: str = "VULNERABILITY",
        page_size: int = 100,
    ) -> list[dict]:
        """
        Fetch vulnerability issues from SonarQube.

        Args:
            project_key: The SonarQube project key
            severities: Comma-separated severity filter (e.g., "CRITICAL,MAJOR")
            types: Issue type filter (default: VULNERABILITY)
            page_size: Number of results per page

        Returns:
            List of raw issue dicts from SonarQube
        """
        params = {
            "componentKeys": project_key,
            "types": types,
            "ps": page_size,
            "resolved": "false",  # Only open issues
        }
        if severities:
            params["severities"] = severities

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{self.base_url}/api/issues/search",
                params=params,
                headers={"Authorization": f"Bearer {self.token}"},
            )
            response.raise_for_status()
            data = response.json()

            logger.info(
                f"Fetched {len(data.get('issues', []))} issues "
                f"from SonarQube (total: {data.get('total', 0)})"
            )
            return data.get("issues", [])
