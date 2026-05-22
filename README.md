<p align="center">
  <img src="assets/cfgaudit.png" alt="cfgaudit" width="460">
</p>

# cfgaudit

Security auditor for AI-agent configuration files.

cfgaudit scans the configuration of AI coding assistants — starting with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) — and flags settings that violate the principle of least privilege or leave sensitive files exposed to the agent's context.

Every finding maps to an [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) risk.

---

## Install

```sh
go install github.com/cfgaudit/cfgaudit/cmd/cfgaudit@latest
```

Pre-built binaries will be available on the [releases page](https://github.com/cfgaudit/cfgaudit/releases) once the first stable version is tagged.

---

## Usage

```sh
# Audit the current directory
cfgaudit

# Audit a specific project root
cfgaudit /path/to/project

# Output as JSON (for CI integration)
cfgaudit --format json

# Output as SARIF 2.1.0 (for GitHub Code Scanning)
cfgaudit --format sarif > cfgaudit.sarif

# Override the Claude Code version used for rule gating (otherwise detected via `claude --version`)
cfgaudit --claude-version 2.1.148

# Print cfgaudit version and exit
cfgaudit --version

# Run only specific rules (CSV or repeated; --only and --skip can be combined)
cfgaudit --only CFG001,CFG003
cfgaudit --only CFG001 --only CFG003
cfgaudit --skip CFG006,CFG009
```

**Scope-aware findings**

Each finding carries a `Scope` (`project`, `project-local`, or `user`) reflecting which file it came from. Rules whose blast radius is amplified when the misconfiguration lives in user-global settings append an explanatory note to the message, and `CFG009` (hook command interpolates a shell variable) escalates from `warn` to `error` at user scope — a malicious hook in `~/.claude/settings.json` fires on every project the user opens.

**Version gating**

Some rules require a minimum Claude Code release before they make sense. cfgaudit runs `claude --version` once per invocation, compares the result to each rule's `MinVersion`, and replaces below-threshold rules with a single `info`-severity skip notice. The detected version is logged to stderr at the start of each scan; the `--claude-version` flag overrides detection (useful in CI containers where the binary is not installed). When neither detection nor the flag yields a version, every rule runs unconditionally.

**Exit codes**

| Code | Meaning |
|------|---------|
| `0` | No findings, or only `warn`/`info` |
| `1` | At least one `error`-severity finding |
| `2` | Tool error (file not found, parse error) |

**Suppressing a finding**

Add a comment on the same line or the line above in the relevant config file:

```json
// cfgaudit:ignore CFG001 -- intentional for local dev sandbox
```

---

## What cfgaudit checks

### `settings.json` (Claude Code)

| ID | Severity | Description | OWASP |
|----|----------|-------------|-------|
| [CFG001](docs/rules/CFG001.md) | error | `permissions.allow` contains unrestricted Bash pattern | LLM06 |
| [CFG002](docs/rules/CFG002.md) | warn | `permissions.allow` contains unrestricted `Edit(*)`/`Write(*)` | LLM06 |
| [CFG003](docs/rules/CFG003.md) | error | `enableAllProjectMcpServers: true` — auto-approves all repo MCP servers (CVE-2025-59536) | LLM06 |
| [CFG004](docs/rules/CFG004.md) | error/warn | `defaultMode` set to `bypassPermissions` or `auto` | LLM06 |
| [CFG005](docs/rules/CFG005.md) | error | `ANTHROPIC_BASE_URL` points to a non-Anthropic endpoint (CVE-2026-21852) | LLM02 |
| [CFG006](docs/rules/CFG006.md) | warn | `permissions.deny` is absent or empty — no guardrails block destructive operations | LLM06 |
| [CFG007](docs/rules/CFG007.md) | error | `env` block contains a hardcoded secret (vendor key prefix or `*_TOKEN`/`*_SECRET`/...) | LLM02 |
| [CFG008](docs/rules/CFG008.md) | error | hook command matches a reverse-shell pattern (`/dev/tcp/`, `nc -e`, `bash -i …`, `mkfifo`, `socat exec`) | LLM06 |
| [CFG009](docs/rules/CFG009.md) | warn | hook command interpolates a shell variable (`$VAR` / `${VAR}`) — attacker-influenced data may reach a shell | LLM01 |
| [CFG010](docs/rules/CFG010.md) | warn | MCP server uses unpinned package or image version (`@latest`, `:latest`, no `@version`) | LLM03 |
| [CFG011](docs/rules/CFG011.md) | warn | MCP server `alwaysAllow` is too broad (wildcard, state-mutating tools, or 10+ entries) | LLM06 |
| [CFG012](docs/rules/CFG012.md) | warn | `settings.json` contains an unknown top-level key or a value whose type contradicts the bundled SchemaStore schema | LLM02 |
| [CFG013](docs/rules/CFG013.md) | warn | `.claude/settings.local.json` or `CLAUDE.local.md` exists in the repo but is not excluded by `.gitignore` | LLM02 |

### `.claudeignore`

### MCP server configuration (Claude Code)

---

## OWASP mapping

| ID | Risk |
|----|------|
| LLM01 | [Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM01_2025-Prompt_Injection.html) |
| LLM02 | [Sensitive Information Disclosure](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM02_2025-Sensitive_Information_Disclosure.html) |
| LLM03 | [Supply Chain Vulnerabilities](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM03_2025-Supply_Chain.html) |
| LLM06 | [Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM06_2025-Excessive_Agency.html) |

---

## Test fixtures

Real-world `settings.json` examples live under `testdata/settings/`:

- `valid/` — configurations that must produce **zero** cfgaudit findings (minimal, fully-populated, team, managed-org).
- `invalid/` — one fixture per rule, named `CFG###_<slug>.json`. Each must trigger the rule encoded in its prefix.

`rules/fixtures_test.go` enforces both invariants on every Go test run, so fixtures and rule implementations stay in lockstep.

A separate workflow (`.github/workflows/schema-validation.yml`) validates every file in `valid/` against the [SchemaStore Claude Code settings schema](https://json.schemastore.org/claude-code-settings.json) on push, on pull request, and nightly. If the upstream schema changes, the nightly run opens (or comments on) a tracking issue so the fixtures and rules can be brought back in sync before silent breakage.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, the test loop, and the step-by-step recipe for adding a new rule.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
