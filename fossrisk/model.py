"""Core data types shared by parsers, the policy engine and renderers."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

Decision = Literal["allow", "review", "deny"]
DECISION_RANK: dict[str, int] = {"allow": 0, "review": 1, "deny": 2}


class SBOMError(Exception):
    """The SBOM file could not be read or understood."""


class PolicyError(Exception):
    """The policy file is invalid."""


@dataclass(frozen=True)
class Component:
    name: str
    version: str | None = None
    purl: str | None = None
    license_expression: str | None = None
    license_source: str = "none"  # "concluded" | "declared" | "none"
    scope: str | None = None


@dataclass
class Finding:
    component: Component
    decision: Decision
    categories: list[str]
    licenses: list[str]
    obligations: list[str]
    matched_rule: str
    reason: str

    def to_dict(self) -> dict:
        return {
            **asdict(self.component),
            "decision": self.decision,
            "categories": self.categories,
            "licenses": self.licenses,
            "obligations": self.obligations,
            "matched_rule": self.matched_rule,
            "reason": self.reason,
        }


@dataclass
class Report:
    sbom_path: str
    sbom_format: str
    findings: list[Finding]
    obligations: dict[str, list[str]] = field(default_factory=dict)

    def summary(self) -> dict[str, int]:
        counts = {"total": len(self.findings), "allow": 0, "review": 0, "deny": 0}
        for finding in self.findings:
            counts[finding.decision] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "sbom": self.sbom_path,
            "format": self.sbom_format,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "obligations": self.obligations,
        }
