import re

import pytest

from fossrisk.licenses import parse
from fossrisk.model import Component, PolicyError
from fossrisk.policy import DEFAULT_POLICY, evaluate_component, evaluate_expression, load_policy


def finding(expr, policy=DEFAULT_POLICY, **kw):
    return evaluate_component(Component("pkg", "1.0", license_expression=expr, **kw), policy)


def write_policy(tmp_path, text):
    path = tmp_path / "policy.yaml"
    path.write_text(text)
    return load_policy(path)


@pytest.mark.parametrize("expr,decision", [
    ("MIT", "allow"),
    ("CC0-1.0", "allow"),
    ("LGPL-2.1-only", "review"),
    ("LicenseRef-acme", "review"),
    ("GPL-3.0-only", "deny"),
    ("AGPL-3.0-or-later", "deny"),
    ("CC-BY-NC-4.0", "deny"),
    ("LicenseRef-Proprietary", "deny"),
])
def test_default_policy_decisions(expr, decision):
    assert finding(expr).decision == decision


def test_missing_license_is_review():
    f = finding(None)
    assert (f.decision, f.categories, f.reason) == ("review", ["unknown"], "no license information in SBOM")


def test_unparseable_expression_is_review_with_reason():
    f = finding("(MIT")
    assert f.decision == "review"
    assert f.licenses == ["(MIT"]
    assert "cannot parse" in f.reason


def test_or_picks_most_favorable_option():
    f = finding("GPL-2.0-only OR MIT")
    assert f.decision == "allow"
    assert f.licenses == ["MIT"]
    assert f.reason.startswith("chose MIT from OR")


def test_and_takes_least_favorable_and_unions_obligations():
    f = finding("MIT AND LGPL-2.1-only")
    assert f.decision == "review"
    assert f.categories == ["permissive", "weak-copyleft"]
    assert f.licenses == ["MIT", "LGPL-2.1-only"]
    assert "disclose-source" in f.obligations and "attribution" in f.obligations
    assert f.obligations.count("attribution") == 1


def test_with_exception_downgrades_gpl():
    assert finding("GPL-2.0-only WITH Classpath-exception-2.0").decision == "review"


def test_evaluate_expression_records_rule():
    ev = evaluate_expression(parse("MIT"), DEFAULT_POLICY)
    assert ev.matched_rule == "category:permissive"


def test_license_rule_overrides_category_and_is_normalized(tmp_path):
    policy = write_policy(tmp_path, "allow: [gpl-2.0]\n")
    f = finding("GPL-2.0-only", policy)
    assert (f.decision, f.matched_rule) == ("allow", "license:GPL-2.0-only")


def test_yaml_overrides_merge_with_defaults(tmp_path):
    policy = write_policy(tmp_path, "deny: [weak-copyleft]\n")
    assert finding("LGPL-2.1-only", policy).decision == "deny"
    assert finding("MIT", policy).decision == "allow"


def test_exception_by_purl_prefix(tmp_path):
    policy = write_policy(tmp_path, """
exceptions:
  - match: "pkg:npm/gpl-tool"
    decision: allow
    reason: build-time only
""")
    f = finding("GPL-3.0-only", policy, purl="pkg:npm/gpl-tool@2.0.0")
    assert (f.decision, f.matched_rule, f.reason) == ("allow", "exception:pkg:npm/gpl-tool", "build-time only")


def test_exception_with_version_must_match(tmp_path):
    policy = write_policy(tmp_path, """
exceptions:
  - {match: pkg, version: "9.9", decision: allow, reason: approved}
""")
    assert finding("GPL-3.0-only", policy).decision == "deny"


def test_ignore_scopes(tmp_path):
    policy = write_policy(tmp_path, "ignore_scopes: [excluded]\n")
    f = finding("GPL-3.0-only", policy, scope="excluded")
    assert (f.decision, f.matched_rule) == ("allow", "ignore_scopes:excluded")


@pytest.mark.parametrize("text,message", [
    ("alow: [MIT]\n", "unknown key(s): alow"),
    ("allow: MIT\n", "'allow' must be a list"),
    ("exceptions:\n  - {match: x, decision: allow}\n", "exceptions[0] needs"),
    ("exceptions:\n  - {match: x, decision: maybe, reason: r}\n", "exceptions[0].decision"),
    ("allow: [\n", "not valid YAML"),
    ("- just\n- a list\n", "must be a YAML mapping"),
    ("allow: ['(MIT']\n", "'(MIT' is neither a category nor a license id"),
])
def test_invalid_policies(tmp_path, text, message):
    with pytest.raises(PolicyError, match=re.escape(message)):
        write_policy(tmp_path, text)


def test_missing_policy_file(tmp_path):
    with pytest.raises(PolicyError, match="cannot read policy"):
        load_policy(tmp_path / "nope.yaml")
