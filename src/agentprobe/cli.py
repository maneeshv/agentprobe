"""
AgentProbe CLI — prompt injection red-teaming for AI agents.
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .payloads import get_payloads, get_categories, get_tags, PAYLOADS
from .scanner import Scanner, ScanResult
from .sse_scanner import SSEScanner
from .report import print_report, print_live, to_json, write_json, to_junit_xml


def _log(msg: str, log_file=None) -> None:
    """Print and optionally write to log file. Always flush."""
    print(msg, flush=True)
    if log_file:
        log_file.write(msg + "\n")
        log_file.flush()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentprobe",
        description="🔴 AgentProbe — Prompt injection red-teaming for AI agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a standard JSON API
  agentprobe scan https://api.example.com/chat

  # Scan an SSE streaming endpoint
  agentprobe scan https://api.example.com/stream --sse

  # Scan with a config file
  agentprobe scan --config agentprobe.json

  # OpenAI-compatible API
  agentprobe scan https://api.example.com/v1/chat/completions \\
    --body '{"model":"gpt-4","messages":[{"role":"user","content":"{{PAYLOAD}}"}]}' \\
    --response-path 'choices.0.message.content' \\
    --header 'Authorization: Bearer sk-...'

  # SSE with cookie auth
  agentprobe scan https://api.example.com/chat --sse \\
    --cookie 'session=abc123; token=xyz' \\
    --body '{"event":"textbox","params":{"question":"{{PAYLOAD}}"}}' \\
    --payload-path 'params.question'

  # Only critical severity payloads
  agentprobe scan https://api.example.com/chat --severity critical

  # JSON + JUnit output for CI/CD
  agentprobe scan https://api.example.com/chat -o results.json --junit report.xml --fail-on-leak

  # List available payloads
  agentprobe list
        """,
    )
    parser.add_argument("--version", action="version", version=f"agentprobe {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # === scan command ===
    scan_parser = subparsers.add_parser("scan", help="Scan an agent endpoint for prompt injection vulnerabilities")
    scan_parser.add_argument("endpoint", nargs="?", help="Agent API endpoint URL (optional if --config is used)")
    scan_parser.add_argument("--config", dest="config_file",
                             help="Load scan config from a JSON file")
    scan_parser.add_argument("--sse", action="store_true",
                             help="Use SSE (Server-Sent Events) streaming mode")
    scan_parser.add_argument("--method", default="POST", choices=["GET", "POST"],
                             help="HTTP method (default: POST)")
    scan_parser.add_argument("--header", "-H", action="append", default=[], dest="headers",
                             help="HTTP header (repeatable), e.g. 'Authorization: Bearer sk-...'")
    scan_parser.add_argument("--cookie", dest="cookie_string",
                             help="Cookie string for authentication")
    scan_parser.add_argument("--body", dest="body_template",
                             help='JSON body template with {{PAYLOAD}} placeholder')
    scan_parser.add_argument("--payload-path", dest="payload_path",
                             help="Dot-notation path in body where payload is inserted (SSE mode, default: params.question)")
    scan_parser.add_argument("--response-path", dest="response_path",
                             help="Dot-notation path to extract response text from JSON")
    scan_parser.add_argument("--category", "-c", help="Filter payloads by category")
    scan_parser.add_argument("--severity", "-s", help="Filter by severity (low/medium/high/critical)")
    scan_parser.add_argument("--tag", "-t", help="Filter payloads by tag")
    scan_parser.add_argument("--payload", "-p", action="append", dest="payloads",
                             help="Run specific payload(s) by name (repeatable)")
    scan_parser.add_argument("--domain", "-d",
                             help="Include domain-specific payloads (e.g. 'flexcon')")
    scan_parser.add_argument("--domain-only", action="store_true",
                             help="Only run domain-specific payloads (requires --domain)")
    scan_parser.add_argument("--timeout", type=float, default=60.0,
                             help="Request timeout in seconds (default: 60)")
    scan_parser.add_argument("--concurrency", type=int, default=2,
                             help="Max concurrent requests (default: 2)")
    scan_parser.add_argument("--delay", type=float, default=2.0,
                             help="Delay between requests in seconds (default: 2.0)")
    scan_parser.add_argument("--output-json", "-o", dest="json_output",
                             help="Write JSON results to file")
    scan_parser.add_argument("--junit", dest="junit_output",
                             help="Write JUnit XML to file (for CI/CD)")
    scan_parser.add_argument("--no-color", action="store_true",
                             help="Disable colored output")
    scan_parser.add_argument("--quiet", "-q", action="store_true",
                             help="Only show leaks and summary")
    scan_parser.add_argument("--fail-on-leak", action="store_true",
                             help="Exit with code 1 if any leaks detected")
    scan_parser.add_argument("--no-live", action="store_true",
                             help="Disable live result output")
    scan_parser.add_argument("--log", dest="log_file",
                             help="Write scan log to file (real-time, unbuffered)")

    # === list command ===
    list_parser = subparsers.add_parser("list", help="List available payloads")
    list_parser.add_argument("--category", "-c", help="Filter by category")
    list_parser.add_argument("--severity", "-s", help="Filter by severity")
    list_parser.add_argument("--tag", "-t", help="Filter by tag")
    list_parser.add_argument("--verbose", "-v", action="store_true",
                             help="Show full payload details")
    list_parser.add_argument("--json", action="store_true", dest="as_json",
                             help="Output as JSON")
    list_parser.add_argument("--domain", "-d",
                             help="Include domain-specific payloads (e.g. 'flexcon')")
    list_parser.add_argument("--domain-only", action="store_true",
                             help="Only show domain-specific payloads")

    # === categories command ===
    subparsers.add_parser("categories", help="List payload categories")

    # === tags command ===
    subparsers.add_parser("tags", help="List payload tags")

    # === init command ===
    subparsers.add_parser("init", help="Generate a sample config file")

    return parser


def cmd_list(args: argparse.Namespace) -> None:
    """List payloads."""
    payloads = get_payloads(
        category=args.category,
        severity=args.severity,
        tag=args.tag,
        include_domain=getattr(args, "domain", None),
        domain_only=getattr(args, "domain_only", False),
    )

    if args.as_json:
        data = [
            {
                "name": p.name,
                "category": p.category,
                "severity": p.severity,
                "description": p.description,
                "tags": p.tags,
                "prompt": p.prompt if args.verbose else p.prompt[:80] + "...",
            }
            for p in payloads
        ]
        print(json.dumps(data, indent=2))
        return

    if not payloads:
        print("No payloads match the given filters.")
        return

    print(f"\n  {'Name':<35} {'Category':<25} {'Severity':<10} Description")
    print(f"  {'─' * 35} {'─' * 25} {'─' * 10} {'─' * 40}")
    for p in payloads:
        desc = p.description[:50] + "..." if len(p.description) > 50 else p.description
        print(f"  {p.name:<35} {p.category:<25} {p.severity:<10} {desc}")

    print(f"\n  Total: {len(payloads)} payloads\n")

    if args.verbose:
        print()
        for p in payloads:
            print(f"  ┌─ {p.name}")
            print(f"  │  Category:    {p.category}")
            print(f"  │  Severity:    {p.severity}")
            print(f"  │  Tags:        {', '.join(p.tags)}")
            print(f"  │  Description: {p.description}")
            print(f"  │  Prompt:")
            for line in p.prompt.split("\n"):
                print(f"  │    {line}")
            print(f"  └{'─' * 60}")
            print()


def cmd_categories(args: argparse.Namespace) -> None:
    """List categories."""
    cats = get_categories()
    print(f"\n  Payload Categories ({len(cats)}):\n")
    for cat in cats:
        count = len([p for p in PAYLOADS if p.category == cat])
        print(f"  • {cat} ({count} payloads)")
    print()


def cmd_tags(args: argparse.Namespace) -> None:
    """List tags."""
    tags = get_tags()
    print(f"\n  Payload Tags ({len(tags)}):\n")
    for tag in tags:
        count = len([p for p in PAYLOADS if tag in p.tags])
        print(f"  • {tag} ({count} payloads)")
    print()


def cmd_init(args: argparse.Namespace) -> None:
    """Generate a sample config file."""
    sample = {
        "endpoint": "https://your-agent.example.com/api/chat",
        "mode": "sse",
        "headers": {
            "Origin": "https://your-app.example.com",
            "Referer": "https://your-app.example.com/",
        },
        "cookie": "session_token=your_token_here",
        "body_template": {
            "event": "textbox",
            "params": {
                "question": "{{PAYLOAD}}",
                "thinking_mode": "quick",
            },
        },
        "payload_path": "params.question",
        "response_path": "message.response.data.answer.answer",
        "timeout": 60,
        "concurrency": 2,
        "delay": 2.0,
    }
    path = "agentprobe.json"
    with open(path, "w") as f:
        json.dump(sample, f, indent=2)
    print(f"  Sample config written to: {path}")
    print(f"  Edit it with your endpoint, cookies, and body template.")


def cmd_scan(args: argparse.Namespace) -> None:
    """Run a scan."""
    # Load config file if provided
    config: dict = {}
    if args.config_file:
        from .config import load_config
        config = load_config(args.config_file)

    # Merge config with CLI args (CLI takes precedence)
    endpoint = args.endpoint or config.get("endpoint")
    if not endpoint:
        _log("Error: endpoint is required (positional arg or --config)")
        sys.exit(1)

    use_sse = args.sse or config.get("mode") == "sse"

    # Parse headers from CLI
    headers: dict[str, str] = config.get("headers", {})
    for h in args.headers:
        if ":" in h:
            key, val = h.split(":", 1)
            headers[key.strip()] = val.strip()

    cookie_string = args.cookie_string or config.get("cookie")
    timeout = args.timeout if args.timeout != 60.0 else config.get("timeout", 60.0)
    concurrency = args.concurrency if args.concurrency != 2 else config.get("concurrency", 2)
    delay = args.delay if args.delay != 2.0 else config.get("delay", 2.0)
    response_path = args.response_path or config.get("response_path")

    use_color = not args.no_color and sys.stdout.isatty()
    live = not args.no_live and not args.quiet

    # Open log file if requested
    log_f = None
    log_path = getattr(args, "log_file", None) or config.get("log")
    if log_path:
        log_f = open(log_path, "w", buffering=1)  # line-buffered
        log_f.write(f"# AgentProbe Scan Log — {datetime.now(timezone.utc).isoformat()}\n")
        log_f.write(f"# Target: {endpoint}\n")
        log_f.write(f"# Mode: {'SSE' if use_sse else 'JSON'}\n\n")
        log_f.flush()

    if live:
        _log("", log_f)
        _log(f"  🔴 AgentProbe v{__version__}", log_f)
        _log(f"  Target: {endpoint}", log_f)
        _log(f"  Mode:   {'SSE streaming' if use_sse else 'Standard JSON'}", log_f)
        if log_path:
            _log(f"  Log:    {log_path}", log_f)
        _log("", log_f)

    # Result counter for live progress
    result_count = [0]

    async def on_result(result: ScanResult) -> None:
        result_count[0] += 1
        if result.error:
            line = f"  [{result_count[0]:>3}] ✗ ERROR   {result.payload.name}: {result.error}"
        elif result.leaked:
            n = len(result.findings)
            line = f"  [{result_count[0]:>3}] 🚨 LEAK   {result.payload.name}  [{result.max_severity.upper()}]  ({n} finding{'s' if n > 1 else ''})"
        elif result.refused:
            line = f"  [{result_count[0]:>3}] ✓ REFUSED {result.payload.name}"
        else:
            line = f"  [{result_count[0]:>3}] ? UNCLEAR {result.payload.name}"

        _log(line, log_f)

        # Write full response to log file for review
        if log_f:
            log_f.write(f"    Response ({result.response_time_ms:.0f}ms, HTTP {result.response_status}):\n")
            # Write full response, indented
            for resp_line in result.response_text.split("\n"):
                log_f.write(f"      {resp_line}\n")
            if result.findings:
                log_f.write(f"    Findings:\n")
                for f in result.findings:
                    log_f.write(f"      - {f.pattern_name}: {f.matched_text[:100]}\n")
            log_f.write("\n")
            log_f.flush()

    if use_sse:
        # SSE mode
        body_template = config.get("body_template")
        if args.body_template:
            body_template = json.loads(args.body_template)
        payload_path = args.payload_path or config.get("payload_path", "params.question")

        scanner = SSEScanner(
            endpoint=endpoint,
            headers=headers,
            cookie_string=cookie_string,
            body_template=body_template,
            payload_path=payload_path,
            response_path=response_path,
            timeout=timeout,
            concurrency=concurrency,
            delay=delay,
        )
    else:
        # Standard JSON mode
        body_tpl = args.body_template or config.get("body_template")
        if isinstance(body_tpl, dict):
            body_tpl = json.dumps(body_tpl)

        scanner = Scanner(
            endpoint=endpoint,
            method=args.method,
            headers=headers,
            body_template=body_tpl,
            response_path=response_path,
            timeout=timeout,
            concurrency=concurrency,
            delay=delay,
        )

    # Domain config
    domain = getattr(args, "domain", None) or config.get("domain")
    domain_only = getattr(args, "domain_only", False) or config.get("domain_only", False)

    # Run scan
    results = asyncio.run(scanner.scan(
        category=args.category,
        severity=args.severity,
        tag=args.tag,
        names=args.payloads,
        on_result=on_result,
        include_domain=domain,
        domain_only=domain_only,
    ))

    # Print report
    if not args.quiet:
        print_report(results, use_color=use_color)

    # Write report to log too
    if log_f:
        # Redirect report to log
        import io
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        print_report(results, use_color=False)
        sys.stdout = old_stdout
        log_f.write(buf.getvalue())
        log_f.flush()

    # JSON output
    if args.json_output:
        write_json(results, args.json_output)
        _log(f"  JSON results written to: {args.json_output}", log_f)

    # JUnit XML output
    if args.junit_output:
        xml = to_junit_xml(results)
        with open(args.junit_output, "w") as f:
            f.write(xml)
        _log(f"  JUnit XML written to: {args.junit_output}", log_f)

    if log_f:
        _log(f"\n  Full log written to: {log_path}", log_f)
        log_f.close()

    # Exit code
    if args.fail_on_leak and any(r.leaked for r in results):
        sys.exit(1)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "categories":
        cmd_categories(args)
    elif args.command == "tags":
        cmd_tags(args)
    elif args.command == "init":
        cmd_init(args)


if __name__ == "__main__":
    main()
