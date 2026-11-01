# Usage

How to run cfgaudit: every flag, the output formats, the subcommands, exit codes and the configuration file. The [README](../README.md) has the short version.

```sh
# Audit the current directory
cfgaudit

# Audit a specific project root
cfgaudit /path/to/project

# Flags go before or after the directory; -- ends them, and one directory at most
cfgaudit /path/to/project --format sarif

# Output format defaults to "auto": a table on an interactive terminal, plain
# text when piped or redirected. Force either with --format table / --format text.
cfgaudit --format table

# Text and table output colour the severity and rule ID on a terminal. Turn it
# off with --no-color or NO_COLOR, or on in a CI log with FORCE_COLOR=1. JSON,
# SARIF and Code Climate are never coloured.
cfgaudit --no-color

# Output as JSON (for CI integration)
cfgaudit --format json

# Output as SARIF 2.1.0 (for GitHub Code Scanning)
cfgaudit --format sarif > cfgaudit.sarif

# Output as Code Climate JSON (for GitLab Code Quality / merge-request findings)
cfgaudit --format codeclimate > gl-code-quality.json

# A finding in a JSON or JSONC file carries the line of the key it reports, so
# GitHub and GitLab show it on the changed line of a pull or merge request. A
# missing key points at its parent, or the finding has no line. TOML and YAML
# findings have no line yet.

# Override the Claude Code version used for rule gating (otherwise detected via `claude --version`)
cfgaudit --claude-version 2.1.148

# Print cfgaudit version and exit
cfgaudit --version

# Run only specific rules (CSV or repeated; --only and --skip can be combined).
# Unknown IDs are reported on stderr; an --only with no known ID exits 2.
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

# Also scan docs that agents read while they work, with the high-precision content rules
cfgaudit --content-paths 'README.md,CONTRIBUTING.md,docs/**/*.md'

# Explain a rule in the terminal (renders its docs)
cfgaudit explain CFG001

# List all rules (filter by OWASP — LLM or MCP — or by agent, or output JSON)
cfgaudit list
cfgaudit list --owasp LLM03
cfgaudit list --owasp MCP05
cfgaudit list --agent cursor
cfgaudit list --format json

# Scaffold a hardened .claude/settings.json for a new project
cfgaudit init                       # write a safe-default deny list (profile: standard)
cfgaudit init --profile minimal     # credential reads only
cfgaudit init --profile paranoid    # + environment runners, shell interpreters, PowerShell
cfgaudit init --dry-run             # print the JSON without writing
cfgaudit init --interactive         # add project-specific deny entries

# Sync deny rules between settings.json and .cfgaudit.yml policy
cfgaudit policy generate            # settings.json permissions.deny -> .cfgaudit.yml require-deny
cfgaudit policy apply --dry-run     # preview: .cfgaudit.yml require-deny -> settings.json permissions.deny
cfgaudit policy apply               # write the missing deny entries
```

**`init` subcommand** — scaffolds `.claude/settings.json` with a hardened `permissions.deny` so a fresh project starts safe-by-default and passes the policy rules (CFG006/CFG041–CFG044) immediately. Aborts if the file exists (use `--force`, or `cfgaudit policy apply` to merge); `--dry-run` prints the JSON; `--interactive` adds project-specific entries.

`--profile` picks how much it writes. Each profile is a superset of the one before it, and every one of them produces a file that scans clean across **all** rules:

| Profile | Entries | What it adds |
|---|---|---|
| `minimal` | 11 | credential reads only: the smallest list that still satisfies CFG006 and CFG041–CFG044 |
| `standard` *(default)* | 32 | + destructive/network/privilege commands, the token stores the coverage rules do not name (`.netrc`, `.npmrc`, `.kube/config`, `.gnupg`, …), `Edit` protection on the same credential paths, and `Edit(**/.claude/**)` so the agent cannot rewrite the list constraining it |
| `paranoid` | 52 | + environment runners (`npx`, `docker exec`, `devbox run`, …), shell interpreters, publish/infra commands, and the PowerShell equivalents |

The runners are in `paranoid` rather than `standard` because they get in the way, not because they matter less. Claude Code strips a fixed set of wrappers before matching a Bash rule but **not** these, and upstream states the consequence: *"a rule like `Bash(devbox run *)` matches whatever comes after `run`, including `devbox run rm -rf .`"*. So every command-class entry in `standard` has a documented bypass through them. PowerShell is likewise a separate tool with its own rules, so nothing in the Bash entries applies to it on Windows.

**What a deny list can and cannot do.** The two halves are not equally strong, and it is worth saying so rather than presenting the file as a boundary:

- **Path rules hold.** `Read`/`Edit` patterns are matched against the resolved path, symlinks included. Their one trap is the anchor: a bare `**/` pattern is anchored at the working directory, so `Read(**/.ssh/**)` in a project file leaves `~/.ssh` readable. The baseline uses the `//` filesystem-root anchor for every location-named entry for exactly this reason ([CFG044](rules/CFG044.md#anchor-the-pattern-at-the-filesystem-root) carries the measurement).
- **Removing a whole tool holds.** A bare `"Bash"` deny entry takes the tool out of the model's context entirely.
- **Argument-constrained Bash rules are guidance.** Matching is a literal prefix, so a reordered or inserted flag walks past a rule that names specific flags. That is why the baseline denies `rm` by name rather than `rm -rf`, and why the force-push entries carry four spellings and still are not airtight. Upstream calls these patterns "fragile" and points at OS-level sandboxing and `PreToolUse` hooks for the part a pattern cannot enforce.

Compound commands are **not** a bypass, contrary to a claim that circulates: with `Bash(touch *)` denied, `touch f && echo ok && ls` was blocked in full on 2.1.231. A rule must match each subcommand independently, and a deny on any one of them blocks the call.

**`policy` subcommand** — keeps `permissions.deny` (enforced by Claude Code) and `policy.require-deny` (audited by cfgaudit / CFG025) in sync. `generate` freezes the current runtime deny list as an auditable policy, preserving the rest of your `.cfgaudit.yml` (comments included). `apply` rolls a policy out to a project's settings; both merge **additively** (nothing is removed) and are idempotent. `apply` rewrites `settings.json` as 2-space-indented JSON with alphabetically-ordered top-level keys — run `--dry-run` first to preview.

**Zed `.zed/settings.json` command sites**

Four fields of Zed's `ProjectSettingsContent` name something the editor launches, and cfgaudit reads all four from a committed file: `context_servers` (through the MCP rules) plus `terminal.shell`, `lsp.<name>.binary` and `dap.<name>`, whose program, argv and `env` ride the command-content family the way `.zed/tasks.json` does.

Two distinctions keep this honest:

- **This file *is* worktree-trust gated**, unlike `.zed/tasks.json`. The findings say "runs on worktree trust" rather than implying zero-click. They are reported anyway on the footing that already applies to `context_servers` in the same file: trust is one prompt covering the whole worktree, granted for any Zed functionality at all, not consent to a specific binary.
- **Only a shell's arguments are shell text.** `lsp.binary.arguments` and `dap.args` go to `execve`, so a `$VAR` or `$(…)` there is literal bytes. cfgaudit passes the full line to the content rules only when the program is an interpreter (`sh`, `bash`, `pwsh`, …), and the program alone otherwise. Without that split, a real config passing `${projectRoot}#python-lsp` to `nix run` reported an interpolation that cannot happen.

**`.zed/debug.json`** is the third committed project file next to `settings.json` and `tasks.json`, and cfgaudit reads one field of it. Upstream: *"Zed will use the `build` field to run any necessary setup steps before the debugger starts"*, and *"Zed allows embedding a Zed task in the `build` field that is run before the debugger starts"*. So pressing Debug on a scenario labelled "Debug server" runs whatever that field names, under a label that describes the session rather than the command. `program`, `args` and `env` are **not** read: they name the binary the user asked to debug, which is the thing they picked, the same line `.zed/tasks.json` draws between a `create_worktree` hook task and one invoked from the task list. A `build` that names an existing task by label is resolved against `.zed/tasks.json` and the finding is attributed to that file, since that is where the command lives. Unlike `settings.json`, `debug.json` is applied **without** a worktree trust check: `update_settings` in `crates/project/src/project_settings.rs` routes only `LocalSettingsKind::Settings` through `can_trust`, while `Tasks` and `Debug` go straight to the task store (#650).

<a id="json-output"></a>**JSON output**

`--format json` prints an array of findings. [`schema/findings.schema.json`](../schema/findings.schema.json) describes it, and CI validates a golden report against it on every change (#1078). From v1.20.0 on the shape is stable: a field may be added in a minor release, and a rename or removal happens only in a major release, announced in the release notes.

| Field | Meaning |
| --- | --- |
| `RuleID` | the rule, `CFG` plus three digits |
| `Severity` | `error`, `warn` or `info`, after `.cfgaudit.yml` overrides |
| `Scope` | `project`, `project-local` or `user` for a finding about a settings scope; omitted otherwise |
| `File` | the file as cfgaudit reached it: the scanned directory as given on the command line joined with the path inside it, or the path of a `--user`, `--config` or `--plugins` input. It is not made relative to the scanned directory (Code Climate output is) |
| `Line`, `Col` | 1-based position, or `0` when the finding is about the whole file or the position is not known |
| `Message` | what was found and how to fix it, with secrets redacted. The wording can change; match on `RuleID` |
| `OWASP` | the rule's OWASP Top 10 for LLM Applications id (`LLM01` to `LLM10`) |
| `AVEID` | the rule's Agentic Vulnerability Enumeration id; omitted for rules without one |

`cfgaudit list --format json` is meant for people and scripts that browse the rule catalogue. Its shape is not covered by the schema and may change.

**Scope-aware findings**

Each finding carries a `Scope` (`project`, `project-local`, or `user`) reflecting which file it came from. Rules whose blast radius is amplified when the misconfiguration lives in user-global settings append an explanatory note to the message, and `CFG009` (hook command interpolates a shell variable) escalates from `warn` to `error` at user scope — a malicious hook in `~/.claude/settings.json` fires on every project the user opens.

**Version gating**

Some rules require a minimum Claude Code release before they make sense. cfgaudit runs `claude --version` once per invocation, compares the result to each rule's `MinVersion`, and replaces below-threshold rules with a single `info`-severity skip notice. The detected version is logged to stderr at the start of each scan; the `--claude-version` flag overrides detection (useful in CI containers where the binary is not installed). When neither detection nor the flag yields a version, every rule runs unconditionally.

**Exit codes**

| Code | Meaning |
|------|---------|
| `0` | No findings, or only `warn`/`info` (without `--strict`) |
| `1` | At least one `error`-severity finding (or any `warn` under `--strict` / `strict: true`) |
| `2` | Usage or tool error: `--format` names an unknown format, the scan path or the `--plugins` path is not a directory, more than one scan path is given, the `--config` file is missing, `.cfgaudit.yml` does not parse or has an unknown key or an invalid severity, `--only` names no known rule, `--shellcheck` analysis fails, or a path in the scan exists but cannot be read (the scan still runs and lists every such path on stderr) |

A directory without any agent configuration exits 0, because that is a valid state, but the text and table formats add `cfgaudit: no agent configuration found in <dir>; nothing was audited` on stderr. A scan in the wrong directory, or after a checkout step that failed, then does not read like a clean repository. JSON, SARIF and Code Climate output are unchanged.

**Credentials in messages**

A finding that quotes a URL from the scanned file shows it with the password and every query value replaced by `***`, and a user name with no password as well, since a token is often written there (`https://***@github.com/...`). Variable references such as `${API_KEY}` stay. Findings end up in SARIF, CI artifacts and logs that more people can read than the repository, so they do not repeat the secret they report.

**Suppressing a finding**

Suppression lives in `.cfgaudit.yml` (below), not in the scanned files: turn a rule off for the project with `rules: { CFG001: off }`, or drop every finding in a file or directory with `exclude-paths`. There is no inline suppression comment, so a scanned file cannot hide its own findings. Since a repository's own `.cfgaudit.yml` can do both, see [scanning a repository you do not trust](#untrusted-repositories).

<a id="configuration-file-cfgaudityml"></a>**Configuration file (`.cfgaudit.yml`)**

cfgaudit auto-discovers a `.cfgaudit.yml` (or `.cfgaudit.yaml`) in the scanned directory; `--config <path>` overrides discovery. CLI flags take precedence over the file.

<a id="schema"></a>**Schema.** [`schema/cfgaudit.schema.json`](../schema/cfgaudit.schema.json) is a JSON Schema for the file, so an editor with YAML schema support (VS Code with the YAML extension, JetBrains IDEs) completes the keys and marks an unknown key, an invalid severity or a malformed policy entry while you type, the same mistakes cfgaudit exits 2 on. Point the file at it with a first line such as:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/cfgaudit/cfgaudit/main/schema/cfgaudit.schema.json
```

Replace `main` with the tag of the release your CI runs, so the editor checks against the keys that release accepts. Rule IDs under `rules` are checked by their form (`CFG` and three digits), not against a list, since cfgaudit only warns about an ID it does not know.

<a id="untrusted-repositories"></a>**Scanning a repository you do not trust.** The discovered file belongs to the repository being scanned, and it decides which rules run and whether findings fail the exit code. A hostile repository can ship one that turns the relevant rules off or sets `no-exit-codes: true`; cfgaudit only names the file it uses on stderr. When you audit a repository before trusting it, such as a fresh clone before you open it with an agent, do not let it configure its own audit:

```sh
cfgaudit --config /dev/null path/to/repo     # an empty config; use NUL on Windows
```

In CI the same applies to changes from people you do not fully trust. Both the [GitHub Action](ci-integration.md#github-action) and the [GitLab components](ci-integration.md#gitlab-cicd-component) take a `config` that the change cannot edit. That protects the scan as far as the pipeline definition is not part of the change too: a pull request that can edit `.cfgaudit.yml` can usually edit the workflow, so review changes to either like code, and use required workflows or protected pipeline configuration where the scan must hold against the change itself.

```yaml path=.cfgaudit.yml
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
# ShellCheck codes CFG045 never reports (with or without the SC prefix)
shellcheck-exclude: [SC2086]

# Files that are not agent instruction files but that agents read while they
# work. Off by default. Only the rules for text with no place in any Markdown
# file run on them (CFG024, CFG032, CFG057, CFG080), and they report warn at most.
content-paths:
  - README.md
  - docs/**/*.md

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

For a team on more than one agent, the policy can be written once and checked against each agent's committed permission file. Claude Code and Devin CLI are checked today; Zed and Continue, which keep permission rules in user settings only, get a CFG118 info finding:

```yaml path=.cfgaudit.yml
policy:
  deny:
    commands: ["git push"]
    read: ["**/.env", "~/.ssh/**"]
    write: ["src/generated/**"]
    fetch: ["*.example.com"]
    mcp-tools: ["github:delete_*"]
  forbid-allow:
    commands: ["curl"]
  agents: [claude-code, devin]   # optional; default: every agent with config in the repo
```

[CFG025](rules/CFG025.md) lists the entry each agent needs for each category.

cfgaudit rejects a `.cfgaudit.yml` with a key it does not know or a severity other than `error`, `warn` or `info`, and exits 2 with the file and the line: `cfgaudit: .cfgaudit.yml:1: unknown key "stirct"`. A typo in the file that sets your exit code must not turn a check off without a word. A key added in a newer cfgaudit therefore fails on an older one; pin the cfgaudit version your CI runs together with the config. A rule ID under `rules` that no rule reports is only a warning, so a config that names a rule from a newer release still loads.
