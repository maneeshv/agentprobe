"""
AgentProbe CLI — prompt injection red-teaming for AI agents.
"""

import argparse
import asyncio
import sys

from . import __version__
from .payloads import get_payloads, get_categories, get_tags, PAYLOADS
from .scanner import Scanner
from .report import print_report, print_live, to_json, write_json, to_junit_xml


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentprobe",
        description="🔴 AgentProbe — Prompt injection red-teaming for AI agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan an agent API with default settings
  agentprobe scan https://api.example.com/chat

  # Custom body template (OpenAI-compatible)
  agentprobe scan https://api.example.com/v1/chat/completions \\
    --body '{"model":"gpt-4","messages":[{"role":"user","content":"{{PAYLOAD}}"}]}' \\
    --response-path 'choices.0.message.content' \\
    --header 'Authorization: Bearer sk-...'

  # Scan only critical severity payloads
  agentprobe scan https://api.example.com/chat --severity critical

  # Scan specific category
  agentprobe scan https://api.example.com/chat --category exfiltration

  # List available payloads
  agentprobe list

  # Output results as JSON
  agentprobe scan https://api.example.com/chat --output-json results.json

  # JUnit XML for CI/CD
  agentprobe scan https://api.example.com/chat --junit report.xml

  # Fail CI if any leaks detected
  agentprobe scan https://api.example.com/chat --fail-on-leak
        """,
    )
    parser.add_argument("--version", action="version", version=f"agentprobe {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # === scan command ===
    scan_parser = subparsers.add_parser("scan", help="Scan an agent endpoint for prompt injection vulnerabilities")
    scan_parser.add_argument("endpoint", help="Agent API endpoint URL")
    scan_parser.add_argument("--method", default="POST", choices=["GET", "POST"], help="HTTP method (default: POST)")
    scan_parser.add_argument("--header", "-H", action="append", default=[], dest="headers",
                             help="HTTP header (repeatable), e.g. 'Authorization: Bearer sk-...'")
    scan_parser.add_argument("--body", dest="body_template",
                             help='JSON body template with {{PAYLOAD}} placeholder (default: {"message": "{{PAYLOAD}}"})')
    scan_parser.add_argument("--response-path", dest="response_path",
                             help="Dot-notation path to extract response text (e.g. 'choices.0.message.content')")
    scan_parser.add_argument("--category", "-c", help="Filter payloads by category")
    scan_parser.add_argument("--severity", "-s", help="Filter payloads by minimum severity (low/medium/high/critical)")
    scan_parser.add_argument("--tag", "-t", help="Filter payloads by tag")
    scan_parser.add_argument("--payload", "-p", action="append", dest="payloads",
                             help="Run specific payload(s) by name (repeatable)")
    scan_parser.add_argument("--timeout", type=float, default=30.0, help="Request timeout in seconds (default: 30)")
    scan_parser.add_argument("--concurrency", type=int, default=3, help="Max concurrent requests (default: 3)")
    scan_parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds (default: 1.0)")
    scan_parser.add_argument("--output-json", "-o", dest="json_output", help="Write JSON results to file")
    scan_parser.add_argument("--junit", dest="junit_output", help="Write JUnit XML to file (for CI/CD)")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    scan_parser.add_argument("--quiet", "-q", action="store_true", help="Only show leaks and summary")
    scan_parser.add_argument("--fail-on-leak", action="store_true", help="Exit with code 1 if any leaks detected")
    scan_parser.add_argument("--live", action="store_true", default=True, help="Show results as they come in (default)")
    scan_parser.add_argument("--no-live", action="store_true", help="Disable live output")

    # === list command ===
    list_parser = subparsers.add_parser("list", help="List available payloads")
    list_parser.add_argument("--category", "-c", help="Filter by category")
    list_parser.add_argument("--severity", "-s", help="Filter by severity")
    list_parser.add_argument("--tag", "-t", help="Filter by tag")
    list_parser.add_argument("--verbose", "-v", action="store_true", help="Show full payload details")
    list_parser.add_argument("--json", action="store_true", dest="as_json", help="Output as JSON")

    # === categories command ===
    subparsers.add_parser("categories", help="List payload categories")

    # === tags command ===
    subparsers.add_parser("tags", help="List payload tags")

    return parser


def cmd_list(args: argparse.Namespace) -> None:
    """List payloads."""
    payloads = get_payloads(
        category=args.category,
        severity=args.severity,
        tag=args.tag,
    )

    if args.as_json:
        import json
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


def cmd_scan(args: argparse.Namespace) -> None:
    """Run a scan."""
    # Parse headers
    headers: dict[str, str] = {}
    for h in args.headers:
        if ":" in h:
            key, val = h.split(":", 1)
            headers[key.strip()] = val.strip()

    scanner = Scanner(
        endpoint=args.endpoint,
        method=args.method,
        headers=headers,
        body_template=args.body_template,
        response_path=args.response_path,
        timeout=args.timeout,
        concurrency=args.concurrency,
        delay=args.delay,
    )

    use_color = not args.no_color and sys.stdout.isatty()
    live = args.live and not args.no_live and not args.quiet

    if live:
        print()
        print(f"  🔴 AgentProbe v{__version__}")
        print(f"  Target: {args.endpoint}")
        print()

    # Live callback
    async def on_result(result: ScanResult) -> None:
        if live:
            print_live(result, use_color=use_color)

    # Run scan
    results = asyncio.run(scanner.scan(
        category=args.category,
        severity=args.severity,
        tag=args.tag,
        names=args.payloads,
        on_result=on_result if live else None,
    ))

    # Print report
    if not args.quiet:
        print_report(results, use_color=use_color)

    # JSON output
    if args.json_output:
        write_json(results, args.json_output)
        print(f"  JSON results written to: {args.json_output}")

    # JUnit XML output
    if args.junit_output:
        xml = to_junit_xml(results)
        with open(args.junit_output, "w") as f:
            f.write(xml)
        print(f"  JUnit XML written to: {args.junit_output}")

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


if __name__ == "__main__":
    main()
