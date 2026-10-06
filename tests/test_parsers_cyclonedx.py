import pytest

from fossrisk.detect import load_sbom
from fossrisk.model import Component, SBOMError

JACKSON = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0"
EXPECTED = [
    Component("lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "MIT", "declared"),
    Component("jackson-databind", "2.17.0", JACKSON, "Apache-2.0", "declared"),
    Component("dual", "1.0", None, "MIT OR GPL-2.0-only", "declared"),
    Component("multi", "2.0", None, "MIT AND BSD-3-Clause", "declared"),
    Component("acked", "3.0", None, "LGPL-2.1-only", "concluded"),
    Component("test-runner", "9.0", None, "GPL-3.0-only", "declared", "excluded"),
    Component("nested-child", "0.2", None, None, "none"),
]


def test_cyclonedx_json(fixtures):
    assert load_sbom(fixtures / "cyclonedx.json") == ("cyclonedx-json", EXPECTED)


def test_cyclonedx_xml(fixtures):
    assert load_sbom(fixtures / "cyclonedx.xml") == ("cyclonedx-xml", EXPECTED)


def test_bom_without_components(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6"}')
    assert load_sbom(path) == ("cyclonedx-json", [])


@pytest.mark.parametrize("content,message", [
    ('<foo/>', "XML is not a CycloneDX BOM"),
    ('<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components>', "not valid XML"),
    ('{"bomFormat": "CycloneDX", "components": {"a": 1}}', "'components' must be a list"),
])
def test_cyclonedx_errors(tmp_path, content, message):
    path = tmp_path / "bad"
    path.write_text(content)
    with pytest.raises(SBOMError, match=message):
        load_sbom(path)


def test_non_string_scalars_are_coerced(tmp_path):
    path = tmp_path / "num.json"
    path.write_text('{"bomFormat": "CycloneDX", "components": '
                    '[{"name": 7, "version": 2, "licenses": [{"license": {"id": "MIT"}}]}]}')
    assert load_sbom(path)[1] == [Component("7", "2", None, "MIT", "declared")]
