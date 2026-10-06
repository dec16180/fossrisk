"""SPDX 2.x tag-value documents."""
from __future__ import annotations

from ..model import Component
from .common import drop_product_roots, pick_license


def parse(text: str) -> list[Component]:
    packages: list[dict[str, str]] = []
    roots: set[str] = set()
    current: dict[str, str] | None = None
    in_text = False
    for line in text.splitlines():
        if in_text:
            in_text = "</text>" not in line
            continue
        if line.lstrip().startswith("#") or ":" not in line:
            continue
        tag, value = (part.strip() for part in line.split(":", 1))
        if value.startswith("<text>") and "</text>" not in value:
            in_text = True
            continue
        if tag == "PackageName":
            current = {"name": value}
            packages.append(current)
        elif tag in ("FileName", "SnippetSPDXID"):
            current = None
        elif tag == "Relationship":
            parts = value.split()
            if len(parts) == 3 and parts[0] == "SPDXRef-DOCUMENT" and parts[1] == "DESCRIBES":
                roots.add(parts[2])
        elif current is not None:
            if tag == "ExternalRef":
                parts = value.split()
                if len(parts) >= 3 and parts[1] == "purl":
                    current.setdefault("purl", parts[2])
            else:
                current.setdefault(tag, value)

    items = []
    for pkg in packages:
        expression, source = pick_license(pkg.get("PackageLicenseConcluded"),
                                          pkg.get("PackageLicenseDeclared"))
        items.append((Component(
            name=pkg["name"],
            version=pkg.get("PackageVersion"),
            purl=pkg.get("purl"),
            license_expression=expression,
            license_source=source,
        ), pkg.get("SPDXID") in roots))
    return drop_product_roots(items)
