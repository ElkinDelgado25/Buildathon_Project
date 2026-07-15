"""Unit tests for the HTTP CLI; no database or running API required."""

import json
import unittest

import httpx

from app.cli import APIClient, CLIError, build_parser, execute


class CLITests(unittest.TestCase):
    def test_analyze_sends_expected_payload(self) -> None:
        request_seen = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_seen
            request_seen = request
            return httpx.Response(200, json={"id": "decision-1"})

        args = build_parser().parse_args(
            [
                "findings",
                "analyze",
                "--source",
                "sonarqube",
                "--payload",
                '{"severity":"CRITICAL"}',
            ]
        )
        with APIClient("http://test", transport=httpx.MockTransport(handler)) as client:
            data, display_type = execute(client, args)

        self.assertEqual(data, {"id": "decision-1"})
        self.assertEqual(display_type, "detail")
        self.assertEqual(request_seen.url.path, "/api/v1/findings/analyze")
        self.assertEqual(
            json.loads(request_seen.content),
            {"source": "sonarqube", "raw_payload": {"severity": "CRITICAL"}},
        )

    def test_list_findings_passes_filters(self) -> None:
        request_seen = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_seen
            request_seen = request
            return httpx.Response(200, json=[])

        args = build_parser().parse_args(
            ["findings", "list", "--source", "zap", "--limit", "10", "--offset", "2"]
        )
        with APIClient("http://test", transport=httpx.MockTransport(handler)) as client:
            data, display_type = execute(client, args)

        self.assertEqual(data, [])
        self.assertEqual(display_type, "findings")
        self.assertEqual(dict(request_seen.url.params), {"limit": "10", "offset": "2", "source": "zap"})

    def test_api_error_exposes_fastapi_detail(self) -> None:
        transport = httpx.MockTransport(
            lambda request: httpx.Response(404, json={"detail": "Decision not found"})
        )
        with APIClient("http://test", transport=transport) as client:
            with self.assertRaisesRegex(CLIError, "API error 404: Decision not found"):
                client.request("GET", "/missing")

    def test_payload_must_be_a_json_object(self) -> None:
        args = build_parser().parse_args(
            ["findings", "analyze", "--source", "zap", "--payload", "[]"]
        )
        with APIClient("http://test", transport=httpx.MockTransport(lambda request: None)) as client:
            with self.assertRaisesRegex(CLIError, "must be a JSON object"):
                execute(client, args)

    def test_audit_plan_uses_api_without_database_access(self) -> None:
        request_seen = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_seen
            request_seen = request
            return httpx.Response(201, json={"id": "audit-1"})

        args = build_parser().parse_args(
            ["audits", "plan", "demo-repository", "--type", "sast"]
        )
        with APIClient("http://test", transport=httpx.MockTransport(handler)) as client:
            data, display_type = execute(client, args)

        self.assertEqual(data, {"id": "audit-1"})
        self.assertEqual(display_type, "detail")
        self.assertEqual(request_seen.url.path, "/api/v1/audits/plan")
        self.assertEqual(
            json.loads(request_seen.content),
            {
                "target": "demo-repository",
                "scan_type": "sast",
                "dast_authorized": False,
            },
        )

    def test_rule_sync_targets_configured_scanner_api(self) -> None:
        request_seen = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_seen
            request_seen = request
            return httpx.Response(200, json=[])

        args = build_parser().parse_args(["rules", "sync", "sonarqube"])
        with APIClient("http://test", transport=httpx.MockTransport(handler)) as client:
            execute(client, args)

        self.assertEqual(request_seen.method, "POST")
        self.assertEqual(request_seen.url.path, "/api/v1/rules/sync/sonarqube")

    def test_usage_requests_aggregate_token_endpoint(self) -> None:
        request_seen = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_seen
            request_seen = request
            return httpx.Response(
                200,
                json={
                    "analyzed_decisions": 2,
                    "prompt_tokens": 100,
                    "completion_tokens": 40,
                    "total_tokens": 140,
                },
            )

        args = build_parser().parse_args(["usage"])
        with APIClient("http://test", transport=httpx.MockTransport(handler)) as client:
            data, display_type = execute(client, args)

        self.assertEqual(display_type, "detail")
        self.assertEqual(data["total_tokens"], 140)
        self.assertEqual(request_seen.url.path, "/api/v1/decisions/usage")


if __name__ == "__main__":
    unittest.main()
