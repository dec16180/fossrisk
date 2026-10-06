import json
import subprocess

import pytest

from fossrisk import ai
from fossrisk.ai import AIUnavailable, ai_review
from fossrisk.model import Report

REPORT = Report("s.json", "spdx-json", [])


@pytest.fixture
def claude_found(monkeypatch):
    monkeypatch.setattr(ai.shutil, "which", lambda name: "/usr/local/bin/claude")


def fake_run(monkeypatch, *, returncode=0, stdout="", stderr="", exc=None):
    calls = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        if exc:
            raise exc
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(ai.subprocess, "run", run)
    return calls


def test_success_sends_report_on_stdin(monkeypatch, claude_found):
    calls = fake_run(monkeypatch, stdout="  ## Top risks\nnone\n")
    assert ai_review(REPORT, timeout=42) == "## Top risks\nnone"
    cmd, kwargs = calls[0]
    assert cmd == ["/usr/local/bin/claude", "-p", ai.PROMPT, "--output-format", "text", "--tools", ""]
    assert "--bare" not in cmd
    assert json.loads(kwargs["input"])["sbom"] == "s.json"
    assert kwargs["timeout"] == 42


def test_claude_missing(monkeypatch):
    monkeypatch.setattr(ai.shutil, "which", lambda name: None)
    with pytest.raises(AIUnavailable, match="not found on PATH"):
        ai_review(REPORT)


def test_nonzero_exit(monkeypatch, claude_found):
    fake_run(monkeypatch, returncode=1, stderr="Invalid API key · Please run /login")
    with pytest.raises(AIUnavailable, match="exited with code 1: Invalid API key"):
        ai_review(REPORT)


def test_timeout(monkeypatch, claude_found):
    fake_run(monkeypatch, exc=subprocess.TimeoutExpired("claude", 5))
    with pytest.raises(AIUnavailable, match="within 5s"):
        ai_review(REPORT, timeout=5)


def test_empty_output(monkeypatch, claude_found):
    fake_run(monkeypatch, stdout="   ")
    with pytest.raises(AIUnavailable, match="empty response"):
        ai_review(REPORT)


def test_prompt_forbids_changing_verdicts():
    assert "must not change" in ai.PROMPT
    assert "not legal advice" in ai.PROMPT
