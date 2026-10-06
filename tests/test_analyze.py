import json

import pytest

from fossrisk.analyze import analyze, explain
from fossrisk.licenses import LicenseParseError
from fossrisk.policy import load_policy


def test_analyze_spdx(fixtures):
    report = analyze(fixtures / "spdx.json")
    assert report.sbom_format == "spdx-json"
    assert report.summary() == {"total": 3, "allow": 1, "review": 1, "deny": 1}
    assert [f.component.name for f in report.findings] == ["readline", "mystery", "lodash"]
    assert report.obligations["MIT"] == ["attribution", "include-license-text"]


def test_analyze_cyclonedx_default_policy(fixtures):
    report = analyze(fixtures / "cyclonedx.json")
    decisions = {f.component.name: f.decision for f in report.findings}
    assert decisions == {
        "lodash": "allow", "jackson-databind": "allow", "dual": "allow", "multi": "allow",
        "acked": "review", "nested-child": "review", "test-runner": "deny",
    }


def test_analyze_with_ignore_scopes(fixtures, tmp_path):
    policy_file = tmp_path / "p.yaml"
    policy_file.write_text("ignore_scopes: [excluded]\n")
    report = analyze(fixtures / "cyclonedx.json", load_policy(policy_file))
    assert report.summary()["deny"] == 0


def test_duplicate_components_reported_once(fixtures, tmp_path):
    doc = json.loads((fixtures / "spdx.json").read_text())
    doc["packages"].append(dict(doc["packages"][1]))
    path = tmp_path / "dupes.json"
    path.write_text(json.dumps(doc))
    assert analyze(path).summary()["total"] == 3


def test_explain():
    info = explain("GPL-2.0-only WITH Classpath-exception-2.0")
    assert info["decision"] == "review"
    assert info["licenses"][0]["category"] == "weak-copyleft"
    assert explain("mit")["expression"] == "MIT"


def test_explain_invalid():
    with pytest.raises(LicenseParseError):
        explain("(MIT")
