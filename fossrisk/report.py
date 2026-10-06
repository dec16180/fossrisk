"""Render a Report as a terminal table, JSON, or Markdown."""
from __future__ import annotations

import io
import json

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .model import Finding, Report

FORMATS = ("table", "json", "markdown")
_STYLE = {"allow": "green", "review": "yellow", "deny": "bold red"}


def render(report: Report, fmt: str, color: bool = False) -> str:
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2) + "\n"
    if fmt == "markdown":
        return _markdown(report)
    if fmt == "table":
        return _table(report, color)
    raise ValueError(f"unknown format {fmt!r}")


def _cells(f: Finding) -> tuple[str, str, str, str, str]:
    return (f.decision, f.component.name, f.component.version or "",
            f.component.license_expression or "(none)", f.reason)


def _table(report: Report, color: bool) -> str:
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=color, width=120, highlight=False)
    s = report.summary()
    console.print(f"[bold]{escape(report.sbom_path)}[/] ({report.sbom_format}): {s['total']} components - "
                  f"[green]{s['allow']} allow[/], [yellow]{s['review']} review[/], "
                  f"[bold red]{s['deny']} deny[/]")
    table = Table()
    for column in ("Decision", "Component", "Version", "License", "Reason"):
        table.add_column(column, overflow="fold")
    for f in report.findings:
        decision, *rest = _cells(f)
        table.add_row(f"[{_STYLE[decision]}]{decision}[/]", *(escape(x) for x in rest))
    console.print(table)
    if report.obligations:
        console.print("[bold]Obligations[/]")
        for lic, obligations in report.obligations.items():
            console.print(f"  {escape(lic)}: {', '.join(obligations)}")
    return buf.getvalue()


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _markdown(report: Report) -> str:
    s = report.summary()
    lines = [
        f"# License compliance report: {report.sbom_path}",
        "",
        f"Format: {report.sbom_format}. Components: {s['total']} - "
        f"allow {s['allow']}, review {s['review']}, deny {s['deny']}.",
        "",
        "| Decision | Component | Version | License | Reason |",
        "|---|---|---|---|---|",
    ]
    for f in report.findings:
        lines.append("| " + " | ".join(_md(cell) for cell in _cells(f)) + " |")
    if report.obligations:
        lines += ["", "## Obligations", ""]
        lines += [f"- **{lic}**: {', '.join(obs)}" for lic, obs in report.obligations.items()]
    return "\n".join(lines) + "\n"
