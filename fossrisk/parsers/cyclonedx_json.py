"""CycloneDX 1.4-1.6 JSON documents."""
from __future__ import annotations

from ..model import Component, SBOMError
from .common import cyclonedx_license


def parse(doc: dict) -> list[Component]:
    out: list[Component] = []
    _walk(doc.get("components") or [], out)
    return out


def _walk(components, out: list[Component]) -> None:
    if not isinstance(components, list):
        raise SBOMError("CycloneDX 'components' must be a list")
    for comp in components:
        if not isinstance(comp, dict):
            raise SBOMError("CycloneDX component entries must be objects")
        expression, source = cyclonedx_license(_licenses(comp.get("licenses") or []))
        out.append(Component(
            name=str(comp.get("name") or "<unnamed>"),
            version=comp.get("version"),
            purl=comp.get("purl"),
            license_expression=expression,
            license_source=source,
            scope=comp.get("scope"),
        ))
        _walk(comp.get("components") or [], out)


def _licenses(entries: list) -> list[tuple[str, str | None]]:
    found = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if "expression" in entry:
            found.append((str(entry["expression"]), entry.get("acknowledgement")))
        elif isinstance(entry.get("license"), dict):
            lic = entry["license"]
            text = lic.get("id") or lic.get("name")
            if text:
                found.append((str(text), lic.get("acknowledgement")))
    return found
