import asyncio

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from fossrisk import mcp_server as m


def test_tools_registered():
    tools = asyncio.run(m.server.list_tools())
    assert {t.name for t in tools} == {"analyze_sbom", "list_components", "explain_license",
                                       "check_compatibility"}


def test_analyze_sbom(fixtures):
    assert m.analyze_sbom(str(fixtures / "spdx.json"))["summary"]["deny"] == 1


def test_list_components_filters(fixtures):
    path = str(fixtures / "cyclonedx.json")
    assert [c["name"] for c in m.list_components(path, decision="deny")["components"]] == ["test-runner"]
    assert m.list_components(path, category="weak-copyleft")["count"] == 1
    assert m.list_components(path, name_contains="JACK")["components"][0]["name"] == "jackson-databind"


def test_explain_and_compat():
    assert m.explain_license("MIT")["decision"] == "allow"
    assert len(m.check_compatibility(["GPL-2.0-only", "Apache-2.0"])["conflicts"]) == 1


@pytest.mark.parametrize("call", [
    lambda: m.analyze_sbom("/definitely/missing.json"),
    lambda: m.explain_license("(MIT"),
    lambda: m.check_compatibility(["MIT"], "cloud"),
    lambda: m.analyze_sbom("x.json", policy_path="/definitely/missing.yaml"),
])
def test_errors_become_tool_errors(call):
    with pytest.raises(ToolError):
        call()


def test_call_over_protocol_layer():
    result = asyncio.run(m.server.call_tool("explain_license", {"spdx_expression": "GPL-3.0-only"}))
    assert not result.is_error
    assert '"deny"' in result.content[0].text
