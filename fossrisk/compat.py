"""Static, non-exhaustive license compatibility notes for a set of licenses."""
from __future__ import annotations

from .licenses import LicenseInfo, classify, leaves, parse

DISTRIBUTIONS = ("binary", "saas", "internal")
_GPL = ("GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later")


def _build_table() -> dict[frozenset[str], str]:
    table: dict[frozenset[str], str] = {}
    for gpl in _GPL:
        for other in ("MPL-1.1", "EPL-1.0", "CDDL-1.0", "CDDL-1.1"):
            table[frozenset({gpl, other})] = (
                f"{other} is not compatible with {gpl}; they cannot be combined into one distributed work.")
    for other in ("Apache-2.0", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-3.0-only",
                  "LGPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later"):
        table[frozenset({"GPL-2.0-only", other})] = (
            f"{other} is not compatible with GPL-2.0-only (no 'or later' upgrade path).")
    return table


INCOMPATIBLE = _build_table()


def check_compatibility(licenses: list[str], distribution: str = "binary") -> dict:
    if distribution not in DISTRIBUTIONS:
        raise ValueError(f"distribution must be one of {', '.join(DISTRIBUTIONS)}")
    infos: list[LicenseInfo] = []
    for raw in licenses:
        for lic in leaves(parse(raw)):
            info = classify(lic)
            if info.id not in {i.id for i in infos}:
                infos.append(info)
    ids = {i.id for i in infos}
    conflicts = sorted(({"licenses": sorted(pair), "note": note}
                        for pair, note in INCOMPATIBLE.items() if pair <= ids),
                       key=lambda c: c["licenses"])
    notes = [n for n in (_note(i, distribution) for i in infos) if n]
    if conflicts and distribution != "binary":
        notes.append("License incompatibilities matter mainly when the combined work is distributed.")
    return {
        "distribution": distribution,
        "licenses": [{"id": i.id, "category": i.category} for i in infos],
        "conflicts": conflicts,
        "notes": notes,
        "disclaimer": "Static rule table; not exhaustive and not legal advice.",
    }


def _note(info: LicenseInfo, distribution: str) -> str | None:
    category = info.category
    if category == "unknown":
        return f"{info.id}: unknown license; compatibility cannot be assessed."
    if category in ("non-commercial", "proprietary"):
        return f"{info.id}: {category} terms restrict use; check the license before any use."
    if category == "network-copyleft":
        return (f"{info.id}: users interacting with a modified version over a network "
                "(employees included) must be offered its source.")
    if distribution == "internal":
        return None
    if category == "strong-copyleft":
        if distribution == "saas":
            return f"{info.id}: SaaS use without distribution does not trigger its source obligations."
        return f"{info.id}: distributing a combined work requires releasing it under {info.id}."
    if category == "weak-copyleft" and distribution == "binary":
        return (f"{info.id}: modifications to the licensed files must be released; "
                "linking from proprietary code is usually allowed.")
    return None
