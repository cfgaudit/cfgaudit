# Security Policy

## Reporting a vulnerability

Report security issues through [GitHub's private vulnerability reporting](https://github.com/cfgaudit/cfgaudit/security/advisories/new) rather than a public issue.

Please include the cfgaudit version, the config input that triggers the problem (redacted if it carries real secrets), and what you expected to happen.

## Coordinated disclosure

- **Acknowledgement** within 7 days of the report.
- **Initial assessment** within 14 days: whether it is in scope (see the trust boundary below), how severe it is, and the planned fix.
- **Fix and advisory** within 90 days of the report. The fix ships in a patch release, and the advisory is published at the same time.

Please keep the report private until the advisory is published, or until 90 days have passed, whichever comes first. If a fix needs longer, we say so and agree a date with you. Reporters are credited in the advisory unless they ask not to be.

## Published vulnerabilities

Vulnerabilities in cfgaudit are published as [GitHub Security Advisories](https://github.com/cfgaudit/cfgaudit/security/advisories), with a CVE where one is assigned, the affected and fixed versions, and the workaround or upgrade path. They also reach the GitHub Advisory Database, OSV and the Go vulnerability database, so tools such as Dependabot and govulncheck report them. The release notes of the fixing release link the advisory.

## Trust boundary

The design, the actors and the threat model behind this boundary are in [docs/design.md](docs/design.md).

cfgaudit's job is to read configuration files that it assumes are **hostile**: a `CLAUDE.md`, `.mcp.json`, `settings.json` or hook definition that arrived with a cloned repository is exactly the untrusted input this tool exists to inspect.

What that means concretely:

- **cfgaudit reads config; it never executes it.** Hook commands, MCP server launch lines and credential-helper scripts are parsed and pattern-matched as text. cfgaudit does not run them, spawn the servers, or resolve their environment.
- **It makes no network calls.** The scanner is fully offline: no telemetry, no rule-feed fetches, no registry lookups. (`bin/cfgaudit`, the Claude Code plugin wrapper, is the one exception — it downloads a release binary when none is on `PATH`, verified against the published checksums.)
- **It only reads files under the scanned directory**, plus `~/.claude/settings.json` when `--user` is passed, and an explicit `--config` / `--plugins` path. A committed symbolic link under the scanned directory that resolves outside it is not followed; it is reported as [CFG115](docs/rules/CFG115.md) (before v1.17.1 it was followed, see [GHSA-x9h6-c6v9-v699](https://github.com/cfgaudit/cfgaudit/security/advisories/GHSA-x9h6-c6v9-v699)).
- **`--shellcheck` is opt-in and shells out.** With that flag, hook and helper command strings are passed to the `shellcheck` binary for static analysis. ShellCheck does not execute the script either, but this is the only path where a third-party tool sees the config content.

Therefore, in scope for a report: anything that makes cfgaudit execute scanned content, escape the paths above, leak file contents off the machine, or crash/hang on a crafted config (a scanner that dies on hostile input fails open).

A rule missing a detection, or firing on benign config, is a **correctness bug** — valuable, but please file it as a normal issue rather than an advisory. False negatives are expected: cfgaudit is a static linter over a moving target, not a guarantee.

## Verifying a release

Every release is signed and carries build provenance. See [Verifying a release](README.md#verifying-a-release) for the commands.

## Supported versions

Only the latest release is supported. Bug fixes and security fixes ship in a new release on the current minor line (for example 1.17.1 after 1.17.0); there are no long-term support branches and no backports.

A release stops receiving security updates on the day the next release is published. Upgrading is the fix. A new release can add findings (new rules or newly scanned files), and any change that can turn a passing pipeline red is called out at the top of the release notes. The moving `v1` tag used by the GitHub Action always points to the latest supported release.

## Vulnerability and license findings

What the automated checks report, and what has to happen before a merge or a release:

| Source | Finding | Threshold |
|---|---|---|
| govulncheck (CI, required) | A known vulnerability in Go code cfgaudit actually calls | Blocks the pull request. Fixed by upgrading the module, or recorded in the [VEX document](.vex/cfgaudit.openvex.json) if it cannot affect cfgaudit. |
| Dependency review (CI, pull requests) | An advisory of severity moderate or higher in a dependency the change adds or updates, in any manifest (Go modules, the CI tool locks, workflow actions) | Blocks the pull request. |
| Dependency review | A dependency whose license is not Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC or 0BSD | Blocks the pull request. Another license needs a decision on the pull request and a change to this list. |
| Dependabot alerts | An advisory in an existing dependency | Critical and high: fixed within 7 days. Moderate: within 30 days. Low: with the next release. |
| Trivy (CI, image) | A fixable critical or high vulnerability in the container image's OS packages | Fails CI, so no image is released until the base image or package is updated. |
| golangci-lint with gosec and staticcheck (CI, required) | Any finding | Blocks the pull request. A false positive is suppressed in the code or `.golangci.yml` with the reason next to it. |
| CodeQL (code scanning) | An alert | Critical and high: fixed before the next release. Medium and lower: triaged within 30 days, then fixed or dismissed with a reason. |

**Before a release** nothing above may be open above its threshold. The release workflows enforce part of it: they build only a commit whose CI passed on `main`, which includes govulncheck, golangci-lint and Trivy. The maintainer checks the open Dependabot and code scanning alerts before tagging.

**Not affected** is recorded, not ignored: a vulnerability that a scanner reports but that cannot affect cfgaudit (for example in a code path cfgaudit never calls, or in an image package it never uses) is added to [`.vex/cfgaudit.openvex.json`](.vex/cfgaudit.openvex.json), an [OpenVEX](https://github.com/openvex/spec) document, with the justification, in a pull request.
