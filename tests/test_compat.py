import pytest

from fossrisk.compat import check_compatibility


def test_gpl2_only_with_apache_conflicts():
    result = check_compatibility(["GPL-2.0-only", "Apache-2.0"])
    assert [c["licenses"] for c in result["conflicts"]] == [["Apache-2.0", "GPL-2.0-only"]]
    assert result["disclaimer"].startswith("Static rule table")


def test_or_later_has_upgrade_path():
    assert check_compatibility(["GPL-2.0-or-later", "Apache-2.0"])["conflicts"] == []


def test_deprecated_ids_and_expressions_are_normalized():
    result = check_compatibility(["GPL-2.0", "MIT AND CDDL-1.0"])
    assert ["CDDL-1.0", "GPL-2.0-only"] in [c["licenses"] for c in result["conflicts"]]
    assert [l["id"] for l in result["licenses"]] == ["GPL-2.0-only", "MIT", "CDDL-1.0"]


def test_saas_notes():
    notes = check_compatibility(["GPL-3.0-only", "AGPL-3.0-only"], "saas")["notes"]
    assert any("does not trigger" in n for n in notes)
    assert any("network" in n for n in notes)


def test_unknown_license_note():
    notes = check_compatibility(["LicenseRef-acme"])["notes"]
    assert notes == ["LicenseRef-acme: unknown license; compatibility cannot be assessed."]


def test_invalid_distribution():
    with pytest.raises(ValueError, match="distribution must be one of"):
        check_compatibility(["MIT"], "cloud")
