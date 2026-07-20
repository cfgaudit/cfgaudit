# Security Policy

## Reporting a vulnerability

Report security issues through [GitHub's private vulnerability reporting](https://github.com/cfgaudit/cfgaudit/security/advisories/new) rather than a public issue.

Please include the cfgaudit version, the config input that triggers the problem (redacted if it carries real secrets), and what you expected to happen. We aim to acknowledge within a few days.

## Trust boundary

cfgaudit's job is to read configuration files that it assumes are **hostile**: a `CLAUDE.md`, `.mcp.json`, `settings.json` or hook definition that arrived with a cloned repository is exactly the untrusted input this tool exists to inspect.

What that means concretely:

- **cfgaudit reads config; it never executes it.** Hook commands, MCP server launch lines and credential-helper scripts are parsed and pattern-matched as text. cfgaudit does not run them, spawn the servers, or resolve their environment.
- **It makes no network calls.** The scanner is fully offline: no telemetry, no rule-feed fetches, no registry lookups. (`bin/cfgaudit`, the Claude Code plugin wrapper, is the one exception — it downloads a release binary when none is on `PATH`, verified against the published checksums.)
- **It only reads files under the scanned directory**, plus `~/.claude/settings.json` when `--user` is passed, and an explicit `--config` / `--plugins` path.
- **`--shellcheck` is opt-in and shells out.** With that flag, hook and helper command strings are passed to the `shellcheck` binary for static analysis. ShellCheck does not execute the script either, but this is the only path where a third-party tool sees the config content.

Therefore, in scope for a report: anything that makes cfgaudit execute scanned content, escape the paths above, leak file contents off the machine, or crash/hang on a crafted config (a scanner that dies on hostile input fails open).

A rule missing a detection, or firing on benign config, is a **correctness bug** — valuable, but please file it as a normal issue rather than an advisory. False negatives are expected: cfgaudit is a static linter over a moving target, not a guarantee.

## Verifying a release

Every release is signed and carries build provenance. See [Verifying a release](README.md#verifying-a-release) for the commands.

## Supported versions

Fixes land on the latest release. There are no long-term support branches.
