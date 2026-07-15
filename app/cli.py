"""Command-line client for the Cybersecurity Agent API."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

import httpx


DEFAULT_API_URL = "http://localhost:8000"


class CLIError(Exception):
    """An error that can be shown directly to a CLI user."""


class APIClient:
    """Small synchronous client, intentionally independent from the database."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            transport=transport,
            headers={"Accept": "application/json"},
        )

    def __enter__(self) -> "APIClient":
        self._client.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        self._client.__exit__(*args)

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise CLIError("The API request timed out.") from exc
        except httpx.RequestError as exc:
            raise CLIError(f"Could not connect to the API: {exc}") from exc

        if response.is_error:
            try:
                body = response.json()
                detail = body.get("detail", body) if isinstance(body, dict) else body
            except (json.JSONDecodeError, ValueError):
                detail = response.text or response.reason_phrase
            if isinstance(detail, (dict, list)):
                detail = json.dumps(detail, ensure_ascii=False)
            raise CLIError(f"API error {response.status_code}: {detail}")

        try:
            return response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise CLIError("The API returned an invalid JSON response.") from exc


def _add_pagination(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--limit", type=int, default=50, help="Maximum rows (default: 50)")
    parser.add_argument("--offset", type=int, default=0, help="Rows to skip (default: 0)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybersec-agent",
        description="Operate the Cybersecurity Agent through its HTTP API.",
    )
    parser.add_argument(
        "--api-url",
        default=os.getenv("CYBERSEC_API_URL", DEFAULT_API_URL),
        help="API base URL (env: CYBERSEC_API_URL)",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Print raw JSON output")

    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("health", help="Check API and database health")

    findings = commands.add_parser("findings", help="Analyze and inspect findings")
    finding_commands = findings.add_subparsers(dest="findings_command", required=True)
    finding_list = finding_commands.add_parser("list", help="List findings")
    _add_pagination(finding_list)
    finding_list.add_argument("--source", choices=("sonarqube", "zap"))
    finding_get = finding_commands.add_parser("get", help="Get one finding")
    finding_get.add_argument("finding_id")
    finding_analyze = finding_commands.add_parser("analyze", help="Analyze a JSON finding")
    finding_analyze.add_argument("--source", required=True, choices=("sonarqube", "zap"))
    payload = finding_analyze.add_mutually_exclusive_group(required=True)
    payload.add_argument("--payload", help="Raw payload as a JSON object")
    payload.add_argument("--file", type=Path, help="JSON file; use - to read stdin")

    decisions = commands.add_parser("decisions", help="Inspect AI decisions")
    decision_commands = decisions.add_subparsers(dest="decisions_command", required=True)
    decision_list = decision_commands.add_parser("list", help="List decisions")
    _add_pagination(decision_list)
    decision_get = decision_commands.add_parser("get", help="Get full decision detail")
    decision_get.add_argument("decision_id")
    decision_get.add_argument("--show-prompt", action="store_true", help="Include the stored prompt")

    rules = commands.add_parser("rules", help="Inspect and synchronize scanner rules")
    rule_commands = rules.add_subparsers(dest="rules_command", required=True)
    rules_list = rule_commands.add_parser("list", help="List cached SonarQube/ZAP rules")
    _add_pagination(rules_list)
    rules_list.add_argument("--source", choices=("sonarqube", "zap"))
    rules_list.add_argument("--severity")
    rules_list.add_argument("--cwe-id")
    rules_list.add_argument("--owasp-category")
    rules_sync = rule_commands.add_parser("sync", help="Download rules from a configured scanner")
    rules_sync.add_argument("source", choices=("sonarqube", "zap"))

    audits = commands.add_parser("audits", help="Plan and inspect bounded security audits")
    audit_run_commands = audits.add_subparsers(dest="audits_command", required=True)
    audit_plan = audit_run_commands.add_parser("plan", help="Create an audit without scanning")
    audit_plan.add_argument("target", help="Authorized repository, image, or URL")
    audit_plan.add_argument("--type", dest="scan_type", required=True, choices=("sast", "dast", "full"))
    audit_plan.add_argument("--authorize-dast", action="store_true")
    audit_get = audit_run_commands.add_parser("get", help="Get audit status and decision")
    audit_get.add_argument("audit_id")
    audit_trace = audit_run_commands.add_parser("trace", help="Show full audit evidence")
    audit_trace.add_argument("audit_id")
    audit_add_finding = audit_run_commands.add_parser(
        "add-finding", help="Attach scanner evidence and evaluate policy"
    )
    audit_add_finding.add_argument("audit_id")
    audit_add_finding.add_argument("--source", required=True, choices=("sonarqube", "zap"))
    audit_add_finding.add_argument("--rule-id")
    audit_payload = audit_add_finding.add_mutually_exclusive_group(required=True)
    audit_payload.add_argument("--payload", help="Raw payload as a JSON object")
    audit_payload.add_argument("--file", type=Path, help="JSON file; use - to read stdin")

    audit = commands.add_parser("audit", help="Submit and inspect human reviews")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    audit_list = audit_commands.add_parser("list", help="List all reviews")
    _add_pagination(audit_list)
    audit_decision = audit_commands.add_parser("decision", help="List reviews for a decision")
    audit_decision.add_argument("decision_id")
    audit_review = audit_commands.add_parser("review", help="Review an AI decision")
    audit_review.add_argument("decision_id")
    audit_review.add_argument("--by", required=True, dest="reviewed_by", help="Analyst name or ID")
    audit_review.add_argument(
        "--verdict", required=True, choices=("agree", "disagree", "escalate")
    )
    comment = audit_review.add_mutually_exclusive_group()
    comment.add_argument("--comment")
    comment.add_argument("--comment-file", type=Path)
    return parser


def _read_payload(args: argparse.Namespace) -> dict[str, Any]:
    if args.payload is not None:
        raw = args.payload
    elif str(args.file) == "-":
        raw = sys.stdin.read()
    else:
        try:
            raw = args.file.read_text(encoding="utf-8")
        except OSError as exc:
            raise CLIError(f"Could not read payload file: {exc}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CLIError(f"Invalid payload JSON: {exc.msg} at line {exc.lineno}") from exc
    if not isinstance(payload, dict):
        raise CLIError("The finding payload must be a JSON object.")
    return payload


def _read_comment(args: argparse.Namespace) -> str | None:
    if args.comment_file is None:
        return args.comment
    try:
        return args.comment_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise CLIError(f"Could not read comment file: {exc}") from exc


def execute(client: APIClient, args: argparse.Namespace) -> tuple[Any, str]:
    """Execute a parsed command and return its data and display type."""
    if args.command == "health":
        return client.request("GET", "/health"), "detail"

    if args.command == "findings":
        if args.findings_command == "list":
            params = {"limit": args.limit, "offset": args.offset}
            if args.source:
                params["source"] = args.source
            return client.request("GET", "/api/v1/findings/", params=params), "findings"
        if args.findings_command == "get":
            return client.request("GET", f"/api/v1/findings/{args.finding_id}"), "detail"
        body = {"source": args.source, "raw_payload": _read_payload(args)}
        return client.request("POST", "/api/v1/findings/analyze", json=body), "detail"

    if args.command == "decisions":
        if args.decisions_command == "list":
            params = {"limit": args.limit, "offset": args.offset}
            return client.request("GET", "/api/v1/decisions/", params=params), "decisions"
        data = client.request("GET", f"/api/v1/decisions/{args.decision_id}")
        if not args.show_prompt and isinstance(data, dict):
            data = {key: value for key, value in data.items() if key != "prompt_used"}
        return data, "detail"

    if args.command == "rules":
        if args.rules_command == "sync":
            return client.request("POST", f"/api/v1/rules/sync/{args.source}"), "rules"
        params = {
            "limit": args.limit,
            "offset": args.offset,
            "source": args.source,
            "severity": args.severity,
            "cwe_id": args.cwe_id,
            "owasp_category": args.owasp_category,
        }
        return client.request(
            "GET", "/api/v1/rules", params={key: value for key, value in params.items() if value}
        ), "rules"

    if args.command == "audits":
        if args.audits_command == "plan":
            body = {
                "target": args.target,
                "scan_type": args.scan_type,
                "dast_authorized": args.authorize_dast,
            }
            return client.request("POST", "/api/v1/audits/plan", json=body), "detail"
        if args.audits_command == "get":
            return client.request("GET", f"/api/v1/audits/{args.audit_id}"), "detail"
        if args.audits_command == "trace":
            return client.request("GET", f"/api/v1/audits/{args.audit_id}/trace"), "detail"
        body = {"source": args.source, "raw_payload": _read_payload(args)}
        if args.rule_id:
            body["security_rule_id"] = args.rule_id
        return client.request(
            "POST", f"/api/v1/audits/{args.audit_id}/findings", json=body
        ), "detail"

    if args.audit_command == "list":
        params = {"limit": args.limit, "offset": args.offset}
        return client.request("GET", "/api/v1/audit/reviews", params=params), "reviews"
    if args.audit_command == "decision":
        path = f"/api/v1/audit/decision/{args.decision_id}/reviews"
        return client.request("GET", path), "reviews"
    if len(args.reviewed_by) > 100:
        raise CLIError("--by cannot contain more than 100 characters.")
    body = {
        "decision_id": args.decision_id,
        "reviewed_by": args.reviewed_by,
        "review_verdict": args.verdict,
        "review_comment": _read_comment(args),
    }
    return client.request("POST", "/api/v1/audit/review", json=body), "detail"


TABLE_COLUMNS = {
    "findings": ("id", "source", "created_at"),
    "decisions": ("id", "final_decision", "severity_assessed", "confidence_score", "created_at"),
    "reviews": ("id", "decision_id", "reviewed_by", "review_verdict", "reviewed_at"),
    "rules": ("id", "source", "external_id", "title", "severity", "cwe_id"),
}


def _short(value: Any, maximum: int = 36) -> str:
    text = "-" if value is None else str(value).replace("\n", " ")
    return text if len(text) <= maximum else text[: maximum - 1] + "…"


def render(data: Any, display_type: str, raw_json: bool = False) -> None:
    if raw_json or display_type == "detail":
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return
    rows = data if isinstance(data, list) else [data]
    if not rows:
        print("No results.")
        return
    columns = TABLE_COLUMNS[display_type]
    values = [[_short(row.get(column)) for column in columns] for row in rows]
    widths = [max(len(column), *(len(row[index]) for row in values)) for index, column in enumerate(columns)]
    print("  ".join(column.upper().ljust(widths[index]) for index, column in enumerate(columns)))
    print("  ".join("-" * width for width in widths))
    for row in values:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    try:
        with APIClient(args.api_url, args.timeout) as client:
            data, display_type = execute(client, args)
        render(data, display_type, args.json)
        if args.command == "health" and data.get("status") != "healthy":
            return 1
        return 0
    except CLIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
