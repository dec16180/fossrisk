"""Run the full pipeline: parse the SBOM, evaluate each component, build a Report."""
from __future__ import annotations

from pathlib import Path

from .detect import load_sbom
from .licenses import LicenseParseError, classify, leaves, parse, render
from .model import DECISION_RANK, Finding, Report
from .policy import DEFAULT_POLICY, Policy, evaluate_component, evaluate_expression


def analyze(path: str | Path, policy: Policy | None = None) -> Report:
    policy = policy or DEFAULT_POLICY
    fmt, components = load_sbom(path)
    unique = list(dict.fromkeys(components))  # drop exact duplicates, keep order
    findings = [evaluate_component(c, policy) for c in unique]
    findings.sort(key=lambda f: (-DECISION_RANK[f.decision], f.component.name.casefold()))
    return Report(str(path), fmt, findings, _obligations(findings))


def _obligations(findings: list[Finding]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for finding in findings:
        for text in finding.licenses:
            if text in out:
                continue
            try:
                node = parse(text)
            except LicenseParseError:
                continue
            obligations = [o for lic in leaves(node) for o in classify(lic).obligations]
            if obligations:
                out[text] = list(dict.fromkeys(obligations))
    return dict(sorted(out.items()))


def explain(expression: str, policy: Policy | None = None) -> dict:
    """Classify a license expression and evaluate it against the policy."""
    policy = policy or DEFAULT_POLICY
    node = parse(expression)
    evaluation = evaluate_expression(node, policy)
    licenses = []
    for lic in leaves(node):
        info = classify(lic)
        licenses.append({"id": render(lic), "category": info.category,
                         "obligations": list(info.obligations)})
    return {
        "expression": render(node),
        "licenses": licenses,
        "decision": evaluation.decision,
        "matched_rule": evaluation.matched_rule,
        "reason": evaluation.reason,
    }
