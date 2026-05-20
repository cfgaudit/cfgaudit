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
| [CFG006](docs/rules/CFG006.md) | error | `enableAllProjectMcpServers: true` — auto-approves all repo MCP servers (CVE-2025-59536) | LLM06 |

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

## License

Apache 2.0 — see [LICENSE](LICENSE).
