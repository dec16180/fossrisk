# fossrisk — SBOM License Compliance CLI

Date: 2026-10-06
Status: Draft for review

## Purpose

A command-line tool that reads a Software Bill of Materials (SPDX or CycloneDX),
classifies every component's license, evaluates it against a compliance policy,
and reports violations and obligations. It integrates with Claude through the
user's Claude subscription (Claude Code / Claude Desktop login, no API key) in
two ways: an MCP server for interactive questions, and an optional `--ai`
narrative review.

**Success criteria**

- `fossrisk analyze sbom.json` produces a correct allow/review/deny verdict per
  component, fully offline and deterministic.
- Usable as a CI gate via exit codes.
- `fossrisk mcp` registered in Claude Code/Desktop lets Claude answer questions
  about an SBOM using exact tool output.
- `fossrisk analyze sbom.json --ai` adds a Claude-written review using the
  local `claude` login.

**Principle:** verdicts come only from the deterministic policy engine. Claude
explains and triages; it never decides compliance. AI output is not legal advice
and is labeled as such.

## Scope

In scope:
- SPDX 2.2/2.3 JSON and tag-value; CycloneDX 1.4–1.6 JSON and XML.
- SPDX license expressions (`AND`, `OR`, `WITH`, parentheses, `LicenseRef-*`).
- Built-in license knowledge base (category + obligations) for common licenses.
- Default policy plus YAML override with per-package exceptions.
- Output formats: table (terminal), JSON, Markdown.
- MCP server (stdio) exposing analysis tools.
- `--ai` review via headless `claude -p`.

Out of scope (YAGNI):
- Fetching license data from package registries or ClearlyDefined.
- Source-code / license-text scanning.
- SPDX 3.0, SPDX RDF/YAML, CycloneDX protobuf.
- Web UI, persistent storage.

## Architecture

Python ≥3.11 package `fossrisk`, installed with `pip install -e .`, which
provides the `fossrisk` console script.

```
fossrisk/
  model.py          Component, Finding, Report dataclasses
  detect.py         SBOM format detection
  parsers/
    spdx_json.py
    spdx_tv.py
    cyclonedx_json.py
    cyclonedx_xml.py
  licenses.py       expression parsing, normalization, classification
  data/licenses.yaml  knowledge base: SPDX id -> category, obligations
  policy.py         Policy model, default policy, YAML loader, evaluation
  analyze.py        orchestrates parse -> classify -> evaluate -> Report
  report.py         table / json / markdown renderers
  ai.py             --ai review via `claude -p`
  mcp_server.py     MCP stdio server
  cli.py            argparse entry point
tests/
  fixtures/         small SPDX + CycloneDX samples (incl. malformed)
```

Each unit has one job and a narrow interface. Parsers depend only on `model`.
`licenses` and `policy` know nothing about SBOM formats. `ai` and `mcp_server`
consume `analyze` and never reimplement logic.

### Data model

```python
Component:  name, version, purl | None, license_expression | None,
            license_source ("concluded" | "declared" | "none"), scope | None
Finding:    component, decision ("allow"|"review"|"deny"),
            categories, matched_rule, reason, obligations[]
Report:     sbom_path, sbom_format, findings[], summary counts,
            obligations aggregated by license
```

### Parsing

- Detection: JSON with `spdxVersion` → SPDX JSON; JSON with
  `bomFormat == "CycloneDX"` → CDX JSON; XML root in the CycloneDX namespace →
  CDX XML; text starting with `SPDXVersion:` → SPDX tag-value.
- SPDX: use `licenseConcluded`, falling back to `licenseDeclared`.
  `NOASSERTION` / `NONE` / missing → no license. The document's own root package
  (from `DESCRIBES`) is excluded.
- CycloneDX: `components[].licenses[]` entries of `license.id`,
  `license.name`, or `expression`; multiple entries combine with `AND`. Nested
  components are flattened. Component `scope` is kept (`excluded` / `optional`
  can be relaxed by policy).

### License classification

- Expression parsing uses the `license-expression` library with the SPDX
  license index. Deprecated IDs are normalized (e.g. `GPL-2.0` →
  `GPL-2.0-only`, `GPL-2.0+` → `GPL-2.0-or-later`).
- Common non-SPDX names ("Apache 2.0", "MIT License", "BSD") map to SPDX IDs
  through an alias table; anything else stays unknown.
- Categories: `permissive`, `public-domain`, `weak-copyleft`,
  `strong-copyleft`, `network-copyleft`, `non-commercial` (or other restrictive
  licenses), `proprietary`, `unknown`.
- Obligations per license, drawn from: `attribution`, `include-license-text`,
  `state-changes`, `disclose-source`, `same-license`, `network-disclosure`,
  `patent-notice`.

### Policy evaluation

- Rules map categories or SPDX IDs to `allow` / `review` / `deny`. A rule
  naming an SPDX ID overrides a category rule.
- `OR`: evaluate each option and take the most favorable; record which option
  was chosen.
- `AND`: take the least favorable; obligations are the union.
- `WITH` exceptions: the exception is looked up (e.g. `Classpath-exception-2.0`
  downgrades GPL to weak-copyleft behavior); otherwise the base license
  applies.
- Exceptions: entries matching a purl or name (with an optional version)
  override the decision and must carry a `reason`.
- Default policy, aimed at distributed proprietary software:
  - allow: permissive, public-domain
  - review: weak-copyleft, unknown, missing license
  - deny: strong-copyleft, network-copyleft, non-commercial, proprietary

Example `policy.yaml`:

```yaml
allow: [permissive, public-domain, MPL-2.0]
review: [weak-copyleft, unknown]
deny: [strong-copyleft, network-copyleft, non-commercial]
ignore_scopes: [excluded]
exceptions:
  - match: "pkg:npm/some-gpl-tool"
    decision: allow
    reason: "build-time only, not distributed"
```

## CLI

```
fossrisk analyze <sbom> [--policy FILE] [--format table|json|markdown]
                        [--output FILE] [--fail-on deny|review|never] [--ai]
fossrisk explain <SPDX-ID-or-expression>
fossrisk mcp
```

Exit codes:
- `0`: no finding at or above `--fail-on` (default `deny`).
- `1`: policy failure.
- `2`: input error (unreadable or unrecognized SBOM, invalid policy).
- `3`: `--ai` requested but Claude is unavailable. The deterministic report is
  still printed first.

## Claude integration

### MCP server (`fossrisk mcp`)

A stdio server built on the official `mcp` Python SDK (`FastMCP`). Tools:

| Tool | Input | Returns |
|---|---|---|
| `analyze_sbom` | `path`, `policy_path?` | Report JSON (summary + findings) |
| `list_components` | `path`, `decision?`, `category?`, `name_contains?` | filtered component list |
| `explain_license` | `spdx_expression` | categories, obligations, policy decision |
| `check_compatibility` | `licenses[]`, `distribution` ("binary"/"saas"/"internal") | pairwise conflict notes from a static rule table |

Registration (documented in the README):
- Claude Code: `claude mcp add fossrisk -- fossrisk mcp`
- Claude Desktop: an entry in `claude_desktop_config.json`

Tools are read-only and only touch paths the caller passes in.

### AI review (`--ai`)

1. Compute the Report locally.
2. Run `claude -p "<review prompt>" --output-format text` as a subprocess,
   sending the Report JSON on stdin. This does not use MCP and allows no tools.
3. The prompt asks for: top risks ranked, ambiguous or unknown licenses with
   likely resolutions, concrete remediation steps (replace, isolate, seek
   exception), and a list of obligations. It states that verdicts are given and
   must not be changed.
4. The output is appended under the heading "AI review (not legal advice)".
   - If the `claude` binary is not found, it is not logged in, or it times out
     (default 180s, set with `--ai-timeout`), the tool prints a clear message
     and exits with code 3.

This path uses whatever auth the local `claude` CLI has: the subscription login
on a workstation, or an API key in CI.

## Error handling

- Unrecognized format or malformed file: a one-line error naming the file and
  the reason, exit code 2. No tracebacks unless `--debug` is set.
- Missing license or `NOASSERTION`: becomes an `unknown` finding, never a crash.
- An expression that cannot be parsed: kept verbatim, classified `unknown`, and
  the reason is shown.
- Invalid policy YAML: exit code 2, naming the offending key.
- MCP tool errors are returned as tool errors with a message; the server keeps
  running.

## Testing

pytest, with no network access and no real `claude` calls.
- Parser tests for each format: a fixture produces the expected Components;
  malformed fixtures raise the expected errors.
- License tests: normalization, aliases, `OR` / `AND` / `WITH` handling,
  `LicenseRef`.
- Policy tests: the default decisions, ID-over-category precedence, exceptions,
  `ignore_scopes`.
- CLI tests: exit codes and the shape of JSON output.
- MCP tests: tool functions are called in-process and return the expected JSON.
- AI tests: `subprocess.run` is mocked to check the command line and the stdin
  payload, plus the "claude missing" and timeout paths.

## Dependencies

`mcp`, `license-expression`, `pyyaml`, `rich`; `pytest` for development. XML is
parsed with the standard library `xml.etree`.
