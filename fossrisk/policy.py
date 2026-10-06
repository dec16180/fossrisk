"""Compliance policy: rules, YAML loading, and evaluation of components."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .licenses import CATEGORIES, Lic, LicenseParseError, Node, Or, classify, parse, render
from .model import DECISION_RANK, Component, Decision, Finding, PolicyError

DECISIONS = ("allow", "review", "deny")
_KEYS = {"allow", "review", "deny", "ignore_scopes", "exceptions"}


@dataclass(frozen=True)
class PolicyException:
    match: str
    decision: Decision
    reason: str
    version: str | None = None

    def applies_to(self, c: Component) -> bool:
        if self.version is not None and c.version != self.version:
            return False
        if self.match == c.name:
            return True
        return c.purl is not None and (c.purl == self.match or c.purl.startswith(self.match + "@"))


@dataclass
class Policy:
    rules: dict[str, Decision]
    ignore_scopes: frozenset[str] = frozenset()
    exceptions: tuple[PolicyException, ...] = ()


DEFAULT_RULES: dict[str, Decision] = {
    "public-domain": "allow",
    "permissive": "allow",
    "weak-copyleft": "review",
    "unknown": "review",
    "strong-copyleft": "deny",
    "network-copyleft": "deny",
    "non-commercial": "deny",
    "proprietary": "deny",
}
DEFAULT_POLICY = Policy(rules=dict(DEFAULT_RULES))


def _rule_key(entry: str, path: Path) -> str:
    if entry in CATEGORIES:
        return entry
    try:
        node = parse(entry)
    except LicenseParseError:
        node = None
    if not isinstance(node, Lic):
        raise PolicyError(f"policy {path}: {entry!r} is neither a category nor a license id")
    return classify(node).id


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"cannot read policy {path}: {exc.strerror}") from None
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy {path} is not valid YAML: {exc}") from None
    data = {} if data is None else data
    if not isinstance(data, dict):
        raise PolicyError(f"policy {path} must be a YAML mapping")
    unknown = sorted(set(data) - _KEYS)
    if unknown:
        raise PolicyError(f"policy {path}: unknown key(s): {', '.join(unknown)}")

    rules = dict(DEFAULT_RULES)
    for decision in DECISIONS:
        entries = data.get(decision) or []
        if not isinstance(entries, list):
            raise PolicyError(f"policy {path}: '{decision}' must be a list")
        for entry in entries:
            rules[_rule_key(str(entry), path)] = decision

    scopes = data.get("ignore_scopes") or []
    if not isinstance(scopes, list):
        raise PolicyError(f"policy {path}: 'ignore_scopes' must be a list")

    exceptions = []
    for i, raw in enumerate(data.get("exceptions") or []):
        if not isinstance(raw, dict) or not {"match", "decision", "reason"} <= set(raw):
            raise PolicyError(f"policy {path}: exceptions[{i}] needs 'match', 'decision' and 'reason'")
        if raw["decision"] not in DECISIONS:
            raise PolicyError(f"policy {path}: exceptions[{i}].decision must be one of allow, review, deny")
        version = raw.get("version")
        exceptions.append(PolicyException(str(raw["match"]), raw["decision"], str(raw["reason"]),
                                          None if version is None else str(version)))
    return Policy(rules, frozenset(str(s) for s in scopes), tuple(exceptions))


@dataclass
class Evaluation:
    decision: Decision
    categories: list[str]
    licenses: list[str]
    obligations: list[str]
    matched_rule: str
    reason: str


def _union(lists) -> list[str]:
    out: list[str] = []
    for items in lists:
        for item in items:
            if item not in out:
                out.append(item)
    return out


def evaluate_expression(node: Node, policy: Policy) -> Evaluation:
    if isinstance(node, Lic):
        info = classify(node)
        if info.id in policy.rules:
            decision, rule = policy.rules[info.id], f"license:{info.id}"
        else:
            decision, rule = policy.rules.get(info.category, "review"), f"category:{info.category}"
        return Evaluation(decision, [info.category], [render(node)], list(info.obligations),
                          rule, f"{render(node)} is {info.category}")
    parts = [evaluate_expression(arg, policy) for arg in node.args]
    if isinstance(node, Or):
        best = min(parts, key=lambda e: DECISION_RANK[e.decision])
        return Evaluation(best.decision, best.categories, best.licenses, best.obligations,
                          best.matched_rule, f"chose {' AND '.join(best.licenses)} from OR: {best.reason}")
    worst = max(parts, key=lambda e: DECISION_RANK[e.decision])
    return Evaluation(worst.decision,
                      _union(p.categories for p in parts),
                      _union(p.licenses for p in parts),
                      _union(p.obligations for p in parts),
                      worst.matched_rule, worst.reason)


def evaluate_component(c: Component, policy: Policy) -> Finding:
    if c.scope and c.scope in policy.ignore_scopes:
        return Finding(c, "allow", [], [], [], f"ignore_scopes:{c.scope}",
                       f"scope '{c.scope}' is ignored by policy")
    unknown = policy.rules.get("unknown", "review")
    if c.license_expression is None:
        ev = Evaluation(unknown, ["unknown"], [], [], "category:unknown", "no license information in SBOM")
    else:
        try:
            ev = evaluate_expression(parse(c.license_expression), policy)
        except LicenseParseError as exc:
            ev = Evaluation(unknown, ["unknown"], [c.license_expression], [], "category:unknown", str(exc))
    for exception in policy.exceptions:
        if exception.applies_to(c):
            return Finding(c, exception.decision, ev.categories, ev.licenses, ev.obligations,
                           f"exception:{exception.match}", exception.reason)
    return Finding(c, ev.decision, ev.categories, ev.licenses, ev.obligations, ev.matched_rule, ev.reason)
