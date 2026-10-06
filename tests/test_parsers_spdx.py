import pytest

from fossrisk.detect import load_sbom
from fossrisk.model import Component, SBOMError
from fossrisk.parsers.common import join_and, pick_license

EXPECTED = [
    Component("lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "MIT", "concluded"),
    Component("readline", "8.2", None, "GPL-3.0-or-later", "declared"),
    Component("mystery", "0.1", None, None, "none"),
]


def test_spdx_json(fixtures):
    assert load_sbom(fixtures / "spdx.json") == ("spdx-json", EXPECTED)


def test_spdx_tag_value(fixtures):
    assert load_sbom(fixtures / "spdx.spdx") == ("spdx-tv", EXPECTED)


def test_pick_license():
    assert pick_license("MIT", "GPL-2.0-only") == ("MIT", "concluded")
    assert pick_license("NOASSERTION", " MIT ") == ("MIT", "declared")
    assert pick_license("NONE", None) == (None, "none")


def test_join_and_normalizes_names():
    assert join_and(["MIT"]) == "MIT"
    assert join_and(["MIT License", "Apache License, Version 2.0"]) == "MIT AND Apache-2.0"
    assert join_and(["MIT OR ISC", "BSD-3-Clause"]) == "(MIT OR ISC) AND BSD-3-Clause"
    assert join_and(["NOASSERTION", ""]) is None


def test_utf8_bom_accepted(tmp_path, fixtures):
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + (fixtures / "spdx.json").read_bytes())
    assert load_sbom(path)[0] == "spdx-json"


@pytest.mark.parametrize("content,message", [
    (b"", "file is empty"),
    (b"   \n", "file is empty"),
    (b"\xff\xfe\x00garbage", "not a UTF-8 text file"),
    (b"{not json", "not valid JSON"),
    (b"[1, 2]", "JSON root must be an object"),
    (b'{"hello": "world"}', "neither SPDX"),
    (b"just some text", "unrecognized SBOM format"),
    (b'{"spdxVersion": "SPDX-2.3", "packages": {}}', "'packages' must be a list"),
])
def test_load_errors(tmp_path, content, message):
    path = tmp_path / "input.txt"
    path.write_bytes(content)
    with pytest.raises(SBOMError, match=message) as info:
        load_sbom(path)
    assert str(info.value).startswith(str(path))


def test_missing_file(tmp_path):
    with pytest.raises(SBOMError, match="file not found"):
        load_sbom(tmp_path / "missing.json")


def _write_spdx(tmp_path, packages, describes):
    import json
    path = tmp_path / "doc.spdx.json"
    path.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
                                "packages": packages, "documentDescribes": describes}))
    return path


def test_single_described_package_is_kept(tmp_path):
    path = _write_spdx(tmp_path, [{"SPDXID": "SPDXRef-lib", "name": "vendorlib",
                                   "licenseConcluded": "GPL-3.0-only"}], ["SPDXRef-lib"])
    assert [c.name for c in load_sbom(path)[1]] == ["vendorlib"]


def test_all_described_packages_are_kept_when_nothing_else_exists(tmp_path):
    path = _write_spdx(tmp_path, [
        {"SPDXID": "SPDXRef-a", "name": "a", "licenseConcluded": "GPL-3.0-only"},
        {"SPDXID": "SPDXRef-b", "name": "b", "licenseConcluded": "AGPL-3.0-only"},
    ], ["SPDXRef-a", "SPDXRef-b"])
    assert [c.name for c in load_sbom(path)[1]] == ["a", "b"]


def test_open_source_root_with_dependencies_is_kept(tmp_path):
    path = _write_spdx(tmp_path, [
        {"SPDXID": "SPDXRef-root", "name": "vendorlib", "licenseConcluded": "GPL-3.0-only"},
        {"SPDXID": "SPDXRef-dep", "name": "dep", "licenseConcluded": "MIT"},
    ], ["SPDXRef-root"])
    assert [c.name for c in load_sbom(path)[1]] == ["vendorlib", "dep"]


def test_tag_value_single_described_package_is_kept(tmp_path):
    path = tmp_path / "single.spdx"
    path.write_text("SPDXVersion: SPDX-2.3\nRelationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-lib\n\n"
                    "PackageName: vendorlib\nSPDXID: SPDXRef-lib\nPackageLicenseConcluded: GPL-3.0-only\n")
    assert [c.name for c in load_sbom(path)[1]] == ["vendorlib"]
