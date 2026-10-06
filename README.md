# fossrisk

License compliance checks for SBOMs (SPDX 2.2/2.3 JSON or tag-value, CycloneDX 1.4–1.6
JSON or XML), with Claude integration through your Claude subscription.

The allow/review/deny verdicts come from a deterministic, offline policy engine.
Claude only explains and triages them. Nothing here is legal advice.

## Install

As a global command (recommended; editable, so code changes apply immediately):

```bash
pipx install --editable /path/to/fossrisk
fossrisk --version
```

For development:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```

`python -m fossrisk ...` works as well.

## Usage

```bash
fossrisk analyze sbom.json                      # terminal table
fossrisk analyze sbom.cdx.xml --format markdown -o report.md
fossrisk analyze sbom.spdx --format json --fail-on review
fossrisk analyze sbom.json --ai                 # adds a Claude-written review
fossrisk explain "GPL-2.0-only WITH Classpath-exception-2.0"
```

Exit codes: `0` pass, `1` policy failure (a finding at or above `--fail-on`, default `deny`),
`2` input error, `3` `--ai` requested but Claude unavailable (the report is still printed).
Add `--debug` before the subcommand to see tracebacks.

## Policy

The default policy assumes you distribute proprietary software:

| Decision | Categories |
|---|---|
| allow | public-domain, permissive |
| review | weak-copyleft, unknown, missing license |
| deny | strong-copyleft, network-copyleft, non-commercial, proprietary |

Override it with `--policy policy.yaml`. Entries are categories or SPDX ids, merged over the defaults:

```yaml
allow: [MPL-2.0]
deny: [weak-copyleft]
ignore_scopes: [excluded]          # CycloneDX component scope
exceptions:
  - match: "pkg:npm/some-gpl-tool" # purl (any version) or component name
    version: "1.2.3"               # optional
    decision: allow
    reason: "build-time only, not distributed"
```

## Claude integration

Both integrations use the login of your local Claude Code / Claude Desktop, so a Claude
subscription works and no API key is needed.

### MCP server (interactive)

Claude Code:

```bash
claude mcp add fossrisk -- /absolute/path/to/fossrisk/.venv/bin/fossrisk mcp
```

Claude Desktop: add this to `~/Library/Application Support/Claude/claude_desktop_config.json`
and restart the app:

```json
{
  "mcpServers": {
    "fossrisk": {
      "command": "/absolute/path/to/fossrisk/.venv/bin/fossrisk",
      "args": ["mcp"]
    }
  }
}
```

Tools: `analyze_sbom`, `list_components`, `explain_license`, `check_compatibility`.
Example prompt: *"Use fossrisk on /Users/me/app/sbom.json. Which components block a binary
release, and what are my options for each?"*

### `--ai` review (batch)

`fossrisk analyze sbom.json --ai` computes the report, then pipes it as JSON into
`claude -p` with all tools disabled and appends the answer under
"AI review (not legal advice)". In CI, set `ANTHROPIC_API_KEY` for `claude`, or rely
on the deterministic exit code alone.
