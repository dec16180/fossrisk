"""CycloneDX 1.4-1.6 XML documents."""
from __future__ import annotations

from xml.etree.ElementTree import Element

from ..model import Component
from .common import cyclonedx_license


def parse(root: Element) -> list[Component]:
    ns = root.tag[1:].split("}", 1)[0] if root.tag.startswith("{") else ""

    def q(tag: str) -> str:
        return f"{{{ns}}}{tag}" if ns else tag

    out: list[Component] = []
    _walk(root.find(q("components")), q, out)
    return out


def _walk(container: Element | None, q, out: list[Component]) -> None:
    if container is None:
        return
    for comp in container.findall(q("component")):
        if comp.get("type") == "file":  # evidence files (e.g. Syft's METADATA/RECORD), not packages
            continue
        found: list[tuple[str, str | None]] = []
        licenses = comp.find(q("licenses"))
        if licenses is not None:
            for child in licenses:
                if child.tag == q("expression") and child.text and child.text.strip():
                    found.append((child.text.strip(), child.get("acknowledgement")))
                elif child.tag == q("license"):
                    text = _text(child, q("id")) or _text(child, q("name"))
                    if text:
                        found.append((text, child.get("acknowledgement")))
        expression, source = cyclonedx_license(found)
        out.append(Component(
            name=_text(comp, q("name")) or "<unnamed>",
            version=_text(comp, q("version")),
            purl=_text(comp, q("purl")),
            license_expression=expression,
            license_source=source,
            scope=_text(comp, q("scope")),
        ))
        _walk(comp.find(q("components")), q, out)


def _text(element: Element, tag: str) -> str | None:
    child = element.find(tag)
    if child is None or child.text is None:
        return None
    return child.text.strip() or None
