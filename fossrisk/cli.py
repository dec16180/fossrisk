"""Command-line entry point."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .ai import AIUnavailable, ai_review
from .analyze import analyze, explain
from .licenses import LicenseParseError
from .model import DECISION_RANK, PolicyError, Report, SBOMError
from .policy import DEFAULT_POLICY, Policy, load_policy
from .report import FORMATS, render

EXIT_OK, EXIT_POLICY, EXIT_INPUT, EXIT_AI = 0, 1, 2, 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fossrisk", description="License compliance checks for SPDX and CycloneDX SBOMs.")
    parser.add_argument("--version", action="version", version=f"fossrisk {__version__}")
    parser.add_argument("--debug", action="store_true", help="show tracebacks on errors")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="check an SBOM against the license policy")
    a.add_argument("sbom", help="SPDX (JSON or tag-value) or CycloneDX (JSON or XML) file")
    a.add_argument("--policy", help="policy YAML file (default: built-in policy)")
    a.add_argument("--format", choices=FORMATS, default="table")
    a.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    a.add_argument("--fail-on", choices=("deny", "review", "never"), default="deny",
                   help="exit 1 if any finding is at or above this level (default: deny)")
    a.add_argument("--ai", action="store_true",
                   help="append a Claude-written review using the local `claude` login")
    a.add_argument("--ai-timeout", type=float, default=180.0, metavar="SECONDS")

    e = sub.add_parser("explain", help="classify a license id or SPDX expression")
    e.add_argument("expression")
    e.add_argument("--policy", help="policy YAML file (default: built-in policy)")

    sub.add_parser("mcp", help="run the MCP server on stdio (for Claude Code / Claude Desktop)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "analyze":
            return _analyze(args)
        if args.command == "explain":
            return _explain(args)
        from . import mcp_server  # imported lazily: keeps the other commands fast
        mcp_server.run()
        return EXIT_OK
    except (SBOMError, PolicyError, LicenseParseError, OSError) as exc:
        if args.debug:
            raise
        print(f"fossrisk: error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except Exception as exc:  # never let a crash look like a policy failure (exit 1)
        if args.debug:
            raise
        print(f"fossrisk: error: unexpected {type(exc).__name__}: {exc} "
              "(run with --debug for a traceback)", file=sys.stderr)
        return EXIT_INPUT


def _policy(path: str | None) -> Policy:
    return load_policy(path) if path else DEFAULT_POLICY


def _analyze(args: argparse.Namespace) -> int:
    report = analyze(args.sbom, _policy(args.policy))
    if not report.findings:
        print(f"fossrisk: warning: no components found in {args.sbom}", file=sys.stderr)

    ai_text = ai_error = None
    if args.ai:
        print("fossrisk: asking Claude for a review...", file=sys.stderr)
        try:
            ai_text = ai_review(report, timeout=args.ai_timeout)
        except AIUnavailable as exc:
            ai_error = str(exc)

    if args.format == "json":
        data = report.to_dict()
        if ai_text is not None:
            data["ai_review"] = ai_text
        text = json.dumps(data, indent=2) + "\n"
    else:
        color = args.output is None and sys.stdout.isatty()
        text = render(report, args.format, color=color)
        if ai_text is not None:
            text += f"\n## AI review (not legal advice)\n\n{ai_text}\n"

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    if ai_error is not None:
        print(f"fossrisk: AI review unavailable: {ai_error}", file=sys.stderr)
        return EXIT_AI
    return _exit_code(report, args.fail_on)


def _exit_code(report: Report, fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    threshold = DECISION_RANK[fail_on]
    failed = any(DECISION_RANK[f.decision] >= threshold for f in report.findings)
    return EXIT_POLICY if failed else EXIT_OK


def _explain(args: argparse.Namespace) -> int:
    info = explain(args.expression, _policy(args.policy))
    print(f"{info['expression']}: {info['decision']} ({info['matched_rule']})")
    for lic in info["licenses"]:
        obligations = ", ".join(lic["obligations"]) or "none"
        print(f"  {lic['id']}: {lic['category']}; obligations: {obligations}")
    return EXIT_OK
