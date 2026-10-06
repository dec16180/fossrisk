"""Helpers shared by the SBOM parsers."""
from __future__ import annotations

from ..licenses import normalize

NO_LICENSE = {"", "NOASSERTION", "NONE"}


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


def join_and(expressions: list[str]) -> str | None:
    """Combine several license entries into one AND expression."""
    parts = [normalize(e) for e in (clean(x) for x in expressions) if e is not None]
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return " AND ".join(f"({p})" if " " in p else p for p in parts)


def cyclonedx_license(found: list[tuple[str, str | None]]) -> tuple[str | None, str]:
    """found: (license text, acknowledgement). Concluded entries win over declared ones."""
    concluded = [text for text, ack in found if ack == "concluded"]
    if concluded:
        return join_and(concluded), "concluded"
    expression = join_and([text for text, _ in found])
    return (expression, "declared") if expression else (None, "none")
