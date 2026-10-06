"""Optional narrative review by Claude through the local `claude` CLI.

Uses whatever login the Claude Code CLI has (a Claude subscription on a
workstation, or an API key in CI). The report is computed first and passed on
stdin; Claude gets no tools and cannot change any decision.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from .model import Report

PROMPT = """You are assisting with open source license compliance triage.
Standard input contains a JSON report produced by the deterministic tool fossrisk.
Every finding already has a policy decision (allow/review/deny). These decisions are final:
you must not change or dispute them.

Write a concise review in Markdown with these sections:
1. Top risks - the deny and review findings ranked by business impact, one line each saying why it matters.
2. Unknown or ambiguous licenses - the likely actual license and how to confirm it (e.g. the package's LICENSE file).
3. Remediation - concrete options per risky component: replace it (name an alternative), isolate it,
   buy a commercial license, or request a documented policy exception.
4. Obligations checklist - what must ship with the product (attribution, license texts, NOTICE files, source offers).

Use only facts from the report and say when information is missing.
End with the sentence: This review is not legal advice."""


class AIUnavailable(Exception):
    """Claude could not produce a review."""


def ai_review(report: Report, timeout: float = 180.0, claude_bin: str = "claude") -> str:
    exe = shutil.which(claude_bin)
    if exe is None:
        raise AIUnavailable(f"'{claude_bin}' not found on PATH. "
                            "Install Claude Code and run `claude` once to log in.")
    cmd = [exe, "-p", PROMPT, "--output-format", "text", "--tools", ""]
    try:
        proc = subprocess.run(cmd, input=json.dumps(report.to_dict()), capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise AIUnavailable(f"claude did not answer within {timeout:g}s "
                            "(use --ai-timeout to wait longer)") from None
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()[:500] or "no output"
        raise AIUnavailable(f"claude exited with code {proc.returncode}: {detail}")
    text = proc.stdout.strip()
    if not text:
        raise AIUnavailable("claude returned an empty response")
    return text
