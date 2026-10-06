"""SPDX 2.x JSON documents."""
from __future__ import annotations

from ..model import Component, SBOMError
from .common import drop_product_roots, pick_license, text


def parse(doc: dict) -> list[Component]:
    packages = doc.get("packages")
    if packages is None:
        packages = []
    if not isinstance(packages, list):
        raise SBOMError("SPDX 'packages' must be a list")
    document_id = doc.get("SPDXID", "SPDXRef-DOCUMENT")
    roots = set(doc.get("documentDescribes") or [])
    for rel in doc.get("relationships") or []:
        if (isinstance(rel, dict) and rel.get("relationshipType") == "DESCRIBES"
                and rel.get("spdxElementId") == document_id):
            roots.add(rel.get("relatedSpdxElement"))

    items = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            raise SBOMError("SPDX package entries must be objects")
        expression, source = pick_license(pkg.get("licenseConcluded"), pkg.get("licenseDeclared"))
        items.append((Component(
            name=str(pkg.get("name") or pkg.get("SPDXID") or "<unnamed>"),
            version=text(pkg.get("versionInfo")),
            purl=text(_purl(pkg.get("externalRefs") or [])),
            license_expression=expression,
            license_source=source,
        ), pkg.get("SPDXID") in roots))
    return drop_product_roots(items)


def _purl(refs: list) -> str | None:
    for ref in refs:
        if isinstance(ref, dict) and ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None
