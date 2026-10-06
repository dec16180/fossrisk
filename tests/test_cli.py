import json

import pytest

from fossrisk import cli
from fossrisk.ai import AIUnavailable


def run(capsys, *argv):
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_analyze_table_fails_on_deny(capsys, fixtures):
    code, out, err = run(capsys, "analyze", str(fixtures / "spdx.json"))
    assert code == 1
    assert "readline" in out and err == ""


@pytest.mark.parametrize("fail_on,expected", [("never", 0), ("deny", 1), ("review", 1)])
def test_fail_on(capsys, fixtures, fail_on, expected):
    assert run(capsys, "analyze", str(fixtures / "spdx.json"), "--fail-on", fail_on)[0] == expected


def test_review_threshold_passes_clean_sbom(capsys, tmp_path):
    path = tmp_path / "clean.json"
    path.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [
        {"SPDXID": "SPDXRef-a", "name": "a", "licenseConcluded": "MIT"}]}))
    assert run(capsys, "analyze", str(path), "--fail-on", "review")[0] == 0


def test_json_format(capsys, fixtures):
    code, out, _ = run(capsys, "analyze", str(fixtures / "cyclonedx.xml"), "--format", "json")
    assert json.loads(out)["format"] == "cyclonedx-xml"


def test_output_file(capsys, fixtures, tmp_path):
    target = tmp_path / "report.md"
    code, out, _ = run(capsys, "analyze", str(fixtures / "spdx.json"), "--format", "markdown",
                       "-o", str(target))
    assert out == ""
    assert target.read_text().startswith("# License compliance report")


def test_missing_file_exit_2(capsys, tmp_path):
    code, out, err = run(capsys, "analyze", str(tmp_path / "nope.json"))
    assert code == 2
    assert err.startswith("fossrisk: error: ") and "file not found" in err
    assert "Traceback" not in err


def test_bad_policy_exit_2(capsys, fixtures, tmp_path):
    policy = tmp_path / "p.yaml"
    policy.write_text("bogus: 1\n")
    code, _, err = run(capsys, "analyze", str(fixtures / "spdx.json"), "--policy", str(policy))
    assert code == 2 and "unknown key(s): bogus" in err


def test_debug_reraises(fixtures, tmp_path):
    from fossrisk.model import SBOMError
    with pytest.raises(SBOMError):
        cli.main(["--debug", "analyze", str(tmp_path / "nope.json")])


def test_explain(capsys):
    code, out, _ = run(capsys, "explain", "Apache-2.0 OR GPL-2.0-only")
    assert code == 0
    assert out.splitlines()[0] == "Apache-2.0 OR GPL-2.0-only: allow (category:permissive)"
    assert "GPL-2.0-only: strong-copyleft" in out


def test_explain_invalid_exit_2(capsys):
    code, _, err = run(capsys, "explain", "(MIT")
    assert code == 2 and "cannot parse" in err


def test_ai_appends_review(capsys, fixtures, monkeypatch):
    monkeypatch.setattr(cli, "ai_review", lambda report, timeout: "Replace readline.")
    code, out, err = run(capsys, "analyze", str(fixtures / "spdx.json"), "--ai")
    assert code == 1
    assert out.index("readline") < out.index("## AI review (not legal advice)")
    assert out.rstrip().endswith("Replace readline.")
    assert "asking Claude" in err


def test_ai_in_json(capsys, fixtures, monkeypatch):
    monkeypatch.setattr(cli, "ai_review", lambda report, timeout: "ok")
    _, out, _ = run(capsys, "analyze", str(fixtures / "spdx.json"), "--ai", "--format", "json")
    assert json.loads(out)["ai_review"] == "ok"


def test_ai_unavailable_exit_3(capsys, fixtures, monkeypatch):
    def boom(report, timeout):
        raise AIUnavailable("claude exited with code 1: Please run /login")
    monkeypatch.setattr(cli, "ai_review", boom)
    code, out, err = run(capsys, "analyze", str(fixtures / "spdx.json"), "--ai")
    assert code == 3
    assert "readline" in out
    assert "AI review unavailable: claude exited with code 1" in err


def test_mcp_subcommand_runs_server(monkeypatch):
    import fossrisk.mcp_server
    called = []
    monkeypatch.setattr(fossrisk.mcp_server, "run", lambda: called.append(True))
    assert cli.main(["mcp"]) == 0
    assert called == [True]


def test_empty_sbom_warns(capsys, tmp_path):
    path = tmp_path / "empty.json"
    path.write_text('{"spdxVersion": "SPDX-2.3", "packages": []}')
    code, _, err = run(capsys, "analyze", str(path))
    assert code == 0
    assert "warning: no components found" in err


def test_unexpected_error_exits_2_without_traceback(capsys, fixtures, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("boom")
    monkeypatch.setattr(cli, "analyze", broken)
    code, _, err = run(capsys, "analyze", str(fixtures / "spdx.json"))
    assert code == 2
    assert err.startswith("fossrisk: error: unexpected RuntimeError: boom")
    assert "Traceback" not in err


def test_python_dash_m_entry_point(fixtures):
    import subprocess
    import sys
    from fossrisk import __version__
    version = subprocess.run([sys.executable, "-m", "fossrisk", "--version"],
                             capture_output=True, text=True)
    assert (version.returncode, version.stdout.strip()) == (0, f"fossrisk {__version__}")
    result = subprocess.run([sys.executable, "-m", "fossrisk", "analyze", str(fixtures / "spdx.json")],
                            capture_output=True, text=True)
    assert result.returncode == 1 and "readline" in result.stdout
