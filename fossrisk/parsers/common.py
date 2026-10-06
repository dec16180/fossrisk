"""Helpers shared by the SBOM parsers."""
from __future__ import annotations

import re

from ..licenses import LicenseParseError, classify, leaves, normalize, parse
from ..model import Component

NO_LICENSE = {"", "NOASSERTION", "NONE"}


def text(value) -> str | None:
    """Coerce a scalar SBOM field (sometimes a number) to str; keep None."""
    return None if value is None else str(value)


def clean(value: str | None) -> str | None:
    """Return the stripped license string, or None for empty/NOASSERTION/NONE."""
    if value is None:
        return None
    value = str(value).strip()
    return None if value.upper() in NO_LICENSE else value


def pick_license(concluded: str | None, declared: str | None) -> tuple[str | None, str]:
    """SPDX rule: prefer the concluded license, fall back to the declared one."""
    if (value := clean(concluded)) is not None:
        return value, "concluded"
    if (value := clean(declared)) is not None:
        return value, "declared"
    return None, "none"


def _term(entry: str) -> str:
    """One AND operand. An unparseable entry becomes an (unknown) LicenseRef so it
    cannot invalidate the other entries of the same component."""
    try:
        parse(entry)
    except LicenseParseError:
        slug = re.sub(r"[^A-Za-z0-9.]+", "-", entry).strip("-.") or "unparseable"
        return f"LicenseRef-{slug}"
    return f"({entry})" if " " in entry else entry


def join_and(expressions: list[str]) -> str | None:
    """Combine several license entries into one AND expression."""
    parts = [normalize(e) for e in (clean(x) for x in expressions) if e is not None]
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return " AND ".join(_term(p) for p in parts)


def cyclonedx_license(found: list[tuple[str, str | None]]) -> tuple[str | None, str]:
    """found: (license text, acknowledgement). Concluded entries win over declared ones."""
    concluded = [t for t, ack in found if ack == "concluded"]
    if concluded:
        return join_and(concluded), "concluded"
    expression = join_and([t for t, _ in found])
    return (expression, "declared") if expression else (None, "none")


def _is_own_product(c: Component) -> bool:
    """True when a described root package looks like the product itself:
    no license, or only proprietary/unknown licenses."""
    if c.license_expression is None:
        return True
    try:
        node = parse(c.license_expression)
    except LicenseParseError:
        return True
    return all(classify(lic).category in ("proprietary", "unknown") for lic in leaves(node))


def drop_product_roots(items: list[tuple[Component, bool]]) -> list[Component]:
    """items: (component, is_described_root). Drop a root only when it is the
    product itself and other packages exist; open-source roots (e.g. a supplier's
    SBOM for one library) are always evaluated."""
    has_dependencies = any(not is_root for _, is_root in items)
    return [c for c, is_root in items
            if not (is_root and has_dependencies and _is_own_product(c))]
