"""MCP server exposing fossrisk to Claude Code / Claude Desktop over stdio."""
from __future__ import annotations

from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .analyze import analyze, explain
from .compat import check_compatibility as _check_compatibility
from .model import PolicyError, SBOMError
from .policy import DEFAULT_POLICY, Policy, load_policy

server = MCPServer(
    "fossrisk",
    instructions=(
        "License compliance tools for SPDX and CycloneDX SBOM files. Always pass absolute paths. "
        "The allow/review/deny decisions come from a deterministic policy engine: report them as "
        "given and do not override them. Your explanations are not legal advice."
    ),
)
_ERRORS = (SBOMError, PolicyError, ValueError)  # ValueError covers LicenseParseError


def _policy(policy_path: str | None) -> Policy:
    return load_policy(Path(policy_path).expanduser()) if policy_path else DEFAULT_POLICY


@server.tool()
def analyze_sbom(path: str, policy_path: str | None = None) -> dict:
    """Check an SBOM file (SPDX JSON/tag-value or CycloneDX JSON/XML) for license compliance.

    Returns a summary, one finding per component (decision, licenses, categories,
    obligations, reason) and obligations aggregated by license. Use absolute paths.
    """
    try:
        return analyze(Path(path).expanduser(), _policy(policy_path)).to_dict()
    except _ERRORS as exc:
        raise ToolError(str(exc)) from exc


@server.tool()
def list_components(path: str, decision: str | None = None, category: str | None = None,
                    name_contains: str | None = None, policy_path: str | None = None) -> dict:
    """List an SBOM's components with their license decision.

    Optional filters: decision (allow/review/deny), license category (public-domain, permissive,
    weak-copyleft, strong-copyleft, network-copyleft, non-commercial, proprietary, unknown),
    and a case-insensitive name substring.
    """
    try:
        report = analyze(Path(path).expanduser(), _policy(policy_path))
    except _ERRORS as exc:
        raise ToolError(str(exc)) from exc
    items = [
        f.to_dict() for f in report.findings
        if (decision is None or f.decision == decision)
        and (category is None or category in f.categories)
        and (name_contains is None or name_contains.casefold() in f.component.name.casefold())
    ]
    return {"count": len(items), "components": items}


@server.tool()
def explain_license(spdx_expression: str, policy_path: str | None = None) -> dict:
    """Classify a license id or SPDX expression and show its obligations and policy decision."""
    try:
        return explain(spdx_expression, _policy(policy_path))
    except _ERRORS as exc:
        raise ToolError(str(exc)) from exc


@server.tool()
def check_compatibility(licenses: list[str], distribution: str = "binary") -> dict:
    """Check a set of licenses for known incompatibilities.

    distribution is one of binary, saas or internal. Uses a static rule table that is
    not exhaustive.
    """
    try:
        return _check_compatibility(licenses, distribution)
    except _ERRORS as exc:
        raise ToolError(str(exc)) from exc


def run() -> None:
    server.run()  # stdio transport
