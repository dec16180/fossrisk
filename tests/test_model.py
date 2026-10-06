from fossrisk.model import Component, Finding, Report


def _finding(name: str, decision: str) -> Finding:
    return Finding(Component(name, "1.0"), decision, ["permissive"], ["MIT"],
                   ["attribution"], "category:permissive", "MIT is permissive")


def test_summary_counts_each_decision():
    report = Report("x.json", "spdx-json",
                    [_finding("a", "allow"), _finding("b", "deny"), _finding("c", "deny")])
    assert report.summary() == {"total": 3, "allow": 1, "review": 0, "deny": 2}


def test_to_dict_flattens_component_fields():
    report = Report("x.json", "spdx-json", [_finding("a", "allow")], {"MIT": ["attribution"]})
    data = report.to_dict()
    assert data["sbom"] == "x.json"
    assert data["format"] == "spdx-json"
    assert data["obligations"] == {"MIT": ["attribution"]}
    finding = data["findings"][0]
    assert finding["name"] == "a"
    assert finding["version"] == "1.0"
    assert finding["decision"] == "allow"
    assert finding["licenses"] == ["MIT"]


def test_component_is_hashable_for_deduplication():
    assert len({Component("a", "1"), Component("a", "1")}) == 1
