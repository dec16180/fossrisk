"""Detect the SBOM format and dispatch to the right parser."""
from __future__ import annotations

import json
from pathlib import Path

from .model import Component, SBOMError
from .parsers import spdx_json, spdx_tv


def load_sbom(path: str | Path) -> tuple[str, list[Component]]:
    """Read an SBOM file and return (format name, components)."""
    p = Path(path).expanduser()
    try:
        text = p.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise SBOMError(f"{p}: file not found") from None
    except UnicodeDecodeError:
        raise SBOMError(f"{p}: not a UTF-8 text file") from None
    except OSError as exc:
        raise SBOMError(f"{p}: {exc.strerror}") from None
    stripped = text.lstrip()
    if not stripped:
        raise SBOMError(f"{p}: file is empty")
    try:
        if stripped.startswith(("{", "[")):
            return _from_json(text)
        if stripped.startswith("SPDXVersion:") or "\nSPDXVersion:" in text:
            return "spdx-tv", spdx_tv.parse(text)
    except SBOMError as exc:
        raise SBOMError(f"{p}: {exc}") from None
    raise SBOMError(f"{p}: unrecognized SBOM format (expected SPDX or CycloneDX)")


def _from_json(text: str) -> tuple[str, list[Component]]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SBOMError(f"not valid JSON ({exc.msg} at line {exc.lineno})") from None
    if not isinstance(doc, dict):
        raise SBOMError("JSON root must be an object")
    if "spdxVersion" in doc:
        return "spdx-json", spdx_json.parse(doc)
    raise SBOMError("JSON is neither SPDX (no 'spdxVersion') nor CycloneDX (no 'bomFormat')")
