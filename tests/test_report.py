import json

from fossrisk.analyze import analyze
from fossrisk.model import Component, Finding, Report
from fossrisk.report import render


def test_json(fixtures):
    data = json.loads(render(analyze(fixtures / "spdx.json"), "json"))
    assert data["summary"]["deny"] == 1
    assert data["findings"][0]["name"] == "readline"


def test_markdown(fixtures):
    text = render(analyze(fixtures / "spdx.json"), "markdown")
    assert text.startswith("# License compliance report")
    assert "| deny | readline | 8.2 | GPL-3.0-or-later |" in text
    assert "## Obligations" in text and "- **MIT**: attribution, include-license-text" in text
    assert text.endswith("\n")


def test_markdown_escapes_pipes():
    finding = Finding(Component("a|b"), "review", ["unknown"], [], [], "category:unknown", "x")
    assert "a\\|b" in render(Report("s", "spdx-json", [finding]), "markdown")


def test_table_plain(fixtures):
    text = render(analyze(fixtures / "spdx.json"), "table", color=False)
    assert "readline" in text and "Obligations" in text
    assert "\x1b[" not in text


def test_table_does_not_interpret_markup():
    finding = Finding(Component("[bold]evil[/bold]"), "allow", [], [], [], "r", "ok")
    assert "[bold]evil[/bold]" in render(Report("s", "spdx-json", [finding]), "table")
