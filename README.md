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

# Output as SARIF (for GitHub Code Scanning)
cfgaudit --format sarif
```

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
| [CFG003](docs/rules/CFG003.md) | warn | `permissions.deny` is absent or empty | LLM06 |
| [CFG004](docs/rules/CFG004.md) | error | `env` block contains a hardcoded secret | LLM02 |
| [CFG005](docs/rules/CFG005.md) | warn | Hook command interpolates an unvalidated variable | LLM01 |

### `.claudeignore`

| ID | Severity | Description | OWASP |
|----|----------|-------------|-------|
| [CFG010](docs/rules/CFG010.md) | warn | `.claudeignore` is absent | LLM02 |
| [CFG011](docs/rules/CFG011.md) | error | `.env` files not excluded | LLM02 |
| [CFG012](docs/rules/CFG012.md) | error | Private key files not excluded (`*.pem`, `*.key`, …) | LLM02 |
| [CFG013](docs/rules/CFG013.md) | error | Cloud credential files not excluded | LLM02 |
| [CFG014](docs/rules/CFG014.md) | error | SSH private keys not excluded | LLM02 |

### MCP server configuration (Claude Code)

| ID | Severity | Description | OWASP |
|----|----------|-------------|-------|
| [CFG020](docs/rules/CFG020.md) | warn | MCP server uses `:latest` / unpinned version | LLM03 |
| [CFG021](docs/rules/CFG021.md) | warn | `alwaysAllow` too broad for MCP server | LLM06 |

---

## OWASP mapping

| ID | Risk |
|----|------|
| LLM01 | [Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM01_2025-Prompt_Injection.html) |
| LLM02 | [Sensitive Information Disclosure](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM02_2025-Sensitive_Information_Disclosure.html) |
| LLM03 | [Supply Chain Vulnerabilities](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM03_2025-Supply_Chain.html) |
| LLM06 | [Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM06_2025-Excessive_Agency.html) |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
