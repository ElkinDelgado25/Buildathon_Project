"""Command-line client for the Cybersecurity Agent API."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import shlex
import subprocess
import sys
import textwrap
import threading
import time
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
    parser.add_argument("--no-color", action="store_true", help="Disable terminal colors")

    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("health", help="Check API and database health")
    commands.add_parser("dashboard", help="Show a compact SOC-style operational overview")
    commands.add_parser("console", help="Open a persistent interactive SOC console (Ctrl+C to close)")
    commands.add_parser("usage", help="Show cumulative OpenAI token usage")

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

    if args.command == "dashboard":
        health = client.request("GET", "/health")
        decisions = client.request("GET", "/api/v1/decisions/", params={"limit": 5, "offset": 0})
        findings = client.request("GET", "/api/v1/findings/", params={"limit": 5, "offset": 0})
        reviews = client.request("GET", "/api/v1/audit/reviews", params={"limit": 5, "offset": 0})
        token_usage = client.request("GET", "/api/v1/decisions/usage")
        return {
            "health": health,
            "recent_decisions": decisions,
            "recent_findings": findings,
            "recent_reviews": reviews,
            "token_usage": token_usage,
        }, "dashboard"

    if args.command == "usage":
        return client.request("GET", "/api/v1/decisions/usage"), "detail"

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


class Theme:
    """Minimal ANSI theme; output remains readable when color is disabled."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, value: Any, code: str) -> str:
        text = str(value)
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def good(self, value: Any) -> str:
        return self.paint(value, "1;32")

    def warn(self, value: Any) -> str:
        return self.paint(value, "1;33")

    def bad(self, value: Any) -> str:
        return self.paint(value, "1;31")

    def info(self, value: Any) -> str:
        return self.paint(value, "1;36")

    def muted(self, value: Any) -> str:
        return self.paint(value, "2")


class ActionStatus:
    """A lightweight terminal activity box for long-running console actions."""

    frames = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
    width = 48

    def __init__(self, label: str, theme: Theme) -> None:
        self.label = _short(label, 36)
        self.theme = theme
        self.active = False
        self.thread: threading.Thread | None = None

    def _line(self, symbol: str, message: str, style: str = "info") -> str:
        content = f" {symbol} {message}"[: self.width - 2]
        line = f"│{content.ljust(self.width - 2)}│"
        return getattr(self.theme, style)(line)

    def _spin(self) -> None:
        index = 0
        while self.active:
            line = self._line(self.frames[index % len(self.frames)], f"Ejecutando: {self.label}")
            sys.stdout.write(f"\r{line}")
            sys.stdout.flush()
            index += 1
            time.sleep(0.12)

    def __enter__(self) -> "ActionStatus":
        if not sys.stdout.isatty():
            return self
        self.active = True
        print(self.theme.info("┌" + "─" * (self.width - 2) + "┐"))
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type: object, *_: object) -> None:
        if not self.active:
            return
        self.active = False
        if self.thread:
            self.thread.join()
        if exc_type is None:
            print("\r" + self._line("✓", f"Completado: {self.label}", "good"))
        else:
            print("\r" + self._line("✗", f"Error: {self.label}", "bad"))
        print(self.theme.info("└" + "─" * (self.width - 2) + "┘"))


def _status(value: Any, theme: Theme) -> str:
    text = _short(value)
    lowered = text.lower()
    if lowered in {"healthy", "connected", "agree", "amenaza_confirmada", "critical"}:
        return theme.good(text)
    if lowered in {"degraded", "disagree", "escalate", "high", "medium"}:
        return theme.warn(text)
    if lowered in {"error", "disconnected", "low", "falso_positivo"}:
        return theme.bad(text)
    return text


def _print_banner(theme: Theme) -> None:
    print(theme.info("╔═╗┬ ┬┌┐ ┌─┐┬─┐  ╔═╗┌─┐┌─┐┌┐┌┌┬┐"))
    print(theme.info("║  └┬┘├┴┐├┤ ├┬┘  ╠═╣│ ┬├┤ │││ │ "))
    print(theme.info("╚═╝ ┴ └─┘└─┘┴└─  ╩ ╩└─┘└─┘┘└┘ ┴ "))
    print(theme.muted("Security operations console · human-reviewed AI decisions"))


def _print_logo_art(theme: Theme) -> bool:
    """Render the optional project logo with chafa, if the terminal supports it."""
    asset_dir = Path(__file__).resolve().parent.parent / "assent"
    logo_path = asset_dir / "Logo-terminal.png"
    if not logo_path.is_file():
        logo_path = asset_dir / "Logo.png"
    chafa = shutil.which("chafa")
    if not chafa or not logo_path.is_file():
        return False
    result = subprocess.run(
        [
            chafa,
            str(logo_path),
            "--format=symbols",
            "--size=45x18",
            "--fg-only",
            "--colors=16" if theme.enabled else "--colors=none",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return False
    print(result.stdout.rstrip())
    print(theme.muted("CyberSec Agent · security operations console"))
    return True


def _print_detail(data: dict[str, Any], theme: Theme) -> None:
    title = "DECISION RECORD" if "final_decision" in data else "RESPONSE"
    print(theme.info(f"\n┌─ {title} " + "─" * max(0, 58 - len(title)) + "┐"))
    priority = (
        "id", "final_decision", "severity_assessed", "confidence_score", "suggested_action",
        "status", "database", "llm_provider", "environment", "review_verdict", "reviewed_by",
    )
    printed = set()
    def print_field(key: str, value: Any) -> None:
        label = key.replace("_", " ").upper() + ":"
        rendered = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
        lines = textwrap.wrap(rendered, width=47, break_long_words=False) or ["-"]
        print(f"│ {theme.muted(label):<22} {lines[0]}")
        for line in lines[1:]:
            print(f"│ {'':22} {line}")

    for key in priority:
        if key not in data:
            continue
        printed.add(key)
        value = data[key]
        if key in {"final_decision", "severity_assessed", "status", "database", "review_verdict"}:
            value = _status(value, theme)
        print_field(key, value)
    for key, value in data.items():
        if key in printed or key in {"prompt_used", "finding", "raw_payload"}:
            continue
        print_field(key, value)
    if "finding" in data:
        finding = data["finding"]
        print("│")
        print(f"│ {theme.info('EVIDENCE')}  {finding.get('source', '-')} · {finding.get('id', '-')}")
        raw_lines = textwrap.wrap(
            json.dumps(finding.get("raw_payload", {}), ensure_ascii=False), width=61, break_long_words=False
        )
        print(f"│ {theme.muted('RAW:')} {raw_lines[0] if raw_lines else '-'}")
        for line in raw_lines[1:]:
            print(f"│      {line}")
    print(theme.info("└" + "─" * 72 + "┘"))


def _print_dashboard(data: dict[str, Any], theme: Theme) -> None:
    if not _print_logo_art(theme):
        _print_banner(theme)
    health = data["health"]
    print("\n" + theme.info("SYSTEM STATUS"))
    print(
        f"  API  {_status(health.get('status'), theme):<18} "
        f"DB  {_status(health.get('database'), theme):<18} "
        f"LLM  {health.get('llm_provider', '-') }"
    )
    print("\n" + theme.info("RECENT ACTIVITY"))
    print(f"  Findings:  {len(data['recent_findings']):>2} visible")
    print(f"  Decisions: {len(data['recent_decisions']):>2} visible")
    print(f"  Reviews:   {len(data['recent_reviews']):>2} visible")
    usage = data["token_usage"]
    print("\n" + theme.info("OPENAI TOKEN USAGE"))
    print(
        f"  Total:  {usage['total_tokens']:,}  "
        f"Input: {usage['prompt_tokens']:,}  "
        f"Output: {usage['completion_tokens']:,}  "
        f"Analyses: {usage['analyzed_decisions']:,}"
    )
    if data["recent_decisions"]:
        print("\n" + theme.info("LATEST DECISIONS"))
        for decision in data["recent_decisions"]:
            severity = _status(decision.get("severity_assessed"), theme)
            print(f"  • {severity:<18} {_short(decision.get('final_decision'), 28):<28} {decision.get('id')}")
    print("\n" + theme.muted("Tip: use `decisions get <id>` to inspect the complete evidence trail."))


def render(
    data: Any,
    display_type: str,
    raw_json: bool = False,
    color: bool | None = None,
) -> None:
    if raw_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return
    theme = Theme(sys.stdout.isatty() if color is None else color)
    if display_type == "dashboard":
        _print_dashboard(data, theme)
        return
    if display_type == "detail":
        _print_detail(data, theme)
        return
    rows = data if isinstance(data, list) else [data]
    if not rows:
        print(theme.muted("No results."))
        return
    columns = TABLE_COLUMNS[display_type]
    values = [[_short(row.get(column)) for column in columns] for row in rows]
    widths = [max(len(column), *(len(row[index]) for row in values)) for index, column in enumerate(columns)]
    print(theme.info("  ".join(column.upper().ljust(widths[index]) for index, column in enumerate(columns))))
    print(theme.muted("  ".join("─" * width for width in widths)))
    for row in values:
        painted = [
            _status(value, theme) if columns[index] in {"severity", "severity_assessed", "final_decision", "review_verdict"} else value
            for index, value in enumerate(row)
        ]
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(painted)))


def _console_help() -> None:
    print(
        "\nCommands available inside the console:\n"
        "  dashboard                              Refresh the SOC overview\n"
        "  findings analyze --source ... --payload ...\n"
        "  findings list | findings get <id>\n"
        "  decisions list | decisions get <id>\n"
        "  audit review <decision-id> --by <name> --verdict agree|disagree|escalate\n"
        "  audit decision <decision-id>\n"
        "  usage                                  Show cumulative OpenAI token usage\n"
        "  rules list | rules sync sonarqube|zap\n"
        "  audits plan <target> --type sast|dast|full\n"
        "\nType help to show this message again. Press Ctrl+C to close the console.\n"
    )


def run_console(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    """Run commands against the API without leaving the SOC terminal session."""
    print("Opening CyberSec Agent console. Press Ctrl+C to close.")
    theme = Theme(not args.no_color)
    with APIClient(args.api_url, args.timeout) as client:
        try:
            dashboard_args = parser.parse_args(["dashboard"])
            with ActionStatus("Cargando dashboard", theme):
                data, display_type = execute(client, dashboard_args)
            render(data, display_type, args.json, color=not args.no_color)
            _console_help()
            while True:
                try:
                    line = input("cybersec> ").strip()
                except EOFError:
                    print("\nUse Ctrl+C to close the console.")
                    continue
                if not line:
                    continue
                if line in {"help", "?"}:
                    _console_help()
                    continue
                if line in {"exit", "quit"}:
                    print("Use Ctrl+C to close the console.")
                    continue
                try:
                    command_args = parser.parse_args(shlex.split(line))
                except SystemExit:
                    print("Invalid command. Type help for examples.")
                    continue
                if command_args.command == "console":
                    print("You are already in the interactive console.")
                    continue
                try:
                    with ActionStatus(line, theme):
                        data, display_type = execute(client, command_args)
                    render(data, display_type, args.json or command_args.json, color=not args.no_color)
                except CLIError as exc:
                    print(f"error: {exc}", file=sys.stderr)
        except KeyboardInterrupt:
            print("\nCyberSec Agent console closed.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.command == "console":
        return run_console(parser, args)
    try:
        with APIClient(args.api_url, args.timeout) as client:
            data, display_type = execute(client, args)
        render(data, display_type, args.json, color=not args.no_color)
        if args.command == "health" and data.get("status") != "healthy":
            return 1
        return 0
    except CLIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
