"""SPDX license expression parsing and classification against the bundled knowledge base."""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from importlib import resources

import yaml
from license_expression import ExpressionError, LicenseWithExceptionSymbol, get_spdx_licensing

CATEGORIES = ("public-domain", "permissive", "weak-copyleft", "strong-copyleft",
              "network-copyleft", "non-commercial", "proprietary", "unknown")
COPYLEFT = {"weak-copyleft", "strong-copyleft", "network-copyleft"}


class LicenseParseError(ValueError):
    """A license expression could not be parsed."""


@dataclass(frozen=True)
class Lic:
    id: str
    exception: str | None = None


@dataclass(frozen=True)
class And:
    args: tuple[Node, ...]


@dataclass(frozen=True)
class Or:
    args: tuple[Node, ...]


Node = Lic | And | Or


@dataclass(frozen=True)
class LicenseInfo:
    id: str
    category: str
    obligations: tuple[str, ...]


def _key(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


@cache
def _kb() -> dict:
    text = resources.files("fossrisk").joinpath("data/licenses.yaml").read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    return {
        "licenses": {k.casefold(): (k, v) for k, v in raw["licenses"].items()},
        "exceptions": {k.casefold(): (k, v) for k, v in raw["exceptions"].items()},
        "aliases": {_key(k): v for k, v in raw["aliases"].items()},
    }


@cache
def _licensing():
    return get_spdx_licensing()


def normalize(raw: str) -> str:
    """Map a free-text license name to its SPDX id; return the stripped input if unknown."""
    return _kb()["aliases"].get(_key(raw), raw.strip())


def parse(expression: str) -> Node:
    """Parse an SPDX expression (or a known license name) into a Node tree."""
    text = normalize(expression)
    if not text:
        raise LicenseParseError("empty license expression")
    try:
        parsed = _licensing().parse(text, validate=False)
    except ExpressionError as exc:
        raise LicenseParseError(f"cannot parse license expression {expression!r}: {exc}") from exc
    if parsed is None:
        raise LicenseParseError("empty license expression")
    return _convert(parsed)


def _convert(expr) -> Node:
    licensing = _licensing()
    if isinstance(expr, licensing.AND):
        return And(tuple(_convert(arg) for arg in expr.args))
    if isinstance(expr, licensing.OR):
        return Or(tuple(_convert(arg) for arg in expr.args))
    if isinstance(expr, LicenseWithExceptionSymbol):
        return Lic(normalize(expr.license_symbol.key), expr.exception_symbol.key)
    return Lic(normalize(expr.key))


def render(node: Node) -> str:
    if isinstance(node, Lic):
        return f"{node.id} WITH {node.exception}" if node.exception else node.id
    op = " AND " if isinstance(node, And) else " OR "
    return op.join(f"({render(a)})" if isinstance(a, (And, Or)) else render(a) for a in node.args)


def leaves(node: Node) -> list[Lic]:
    if isinstance(node, Lic):
        return [node]
    return [leaf for arg in node.args for leaf in leaves(arg)]


def classify(lic: Lic) -> LicenseInfo:
    entry = _kb()["licenses"].get(lic.id.casefold())
    if entry is None:
        info = LicenseInfo(lic.id, "unknown", ())
    else:
        canonical, data = entry
        info = LicenseInfo(canonical, data["category"], tuple(data.get("obligations") or ()))
    if lic.exception and info.category in COPYLEFT:
        exception = _kb()["exceptions"].get(lic.exception.casefold())
        if exception is not None:
            info = LicenseInfo(info.id, exception[1]["category"], info.obligations)
    return info
