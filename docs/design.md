# Design and threat model

This page describes who and what acts in cfgaudit, what a scan does from start to finish, how releases are built, and which security problems matter most. The trust boundary itself is stated in [SECURITY.md](../SECURITY.md#trust-boundary); this page explains how the design keeps it.

## Actors

| Actor | What it does |
|---|---|
| **User** | Runs `cfgaudit` on a checkout, by hand or from an editor hook. Chooses flags and an optional `.cfgaudit.yml`. |
| **CI job** | Runs cfgaudit through the GitHub Action, a GitLab CI/CD component or the container image, and acts on the exit code and the report (SARIF, Code Climate). |
| **Repository content** | The configuration files under the scanned directory: agent settings, MCP configs, hooks, instruction files, skills, plugins. **Treated as hostile**: it may have been written by whoever controls the repository being scanned. |
| **cfgaudit CLI** | The Go binary. Reads files, never executes them, writes a report to stdout and an exit code. |
| **`claude`** | When `--claude-version` is not given, cfgaudit runs `claude --version` from `PATH` once to pick version-dependent rule behaviour. Its output is parsed as a version string only. |
| **`shellcheck`** | Only with `--shellcheck`: receives hook and helper command strings on stdin for static analysis (rule CFG045). It does not execute them either. |
| **Claude Code plugin wrapper** (`bin/cfgaudit`) | A shell script that runs an installed cfgaudit, or downloads the release binary for its pinned version and verifies it against `checksums.txt` before running it. |
| **Maintainer** | Merges pull requests and tags releases. See [GOVERNANCE.md](../GOVERNANCE.md). |
| **Release workflows** | GitHub Actions workflows that build, sign and publish a tagged release. |
| **Distribution channels** | GitHub Releases, `ghcr.io/cfgaudit/cfgaudit`, the Homebrew tap, the GitHub Marketplace and the GitLab CI/CD Catalog. |

## What a scan does

1. **Arguments and config.** `run()` in `cmd/cfgaudit/main.go` parses the flags (`--format`, `--only`, `--skip`, `--strict`, `--user`, `--plugins`, `--config`, `--shellcheck`, `--claude-version`), loads `.cfgaudit.yml` from the scan directory or `--config` (`internal/config`), and refuses a scan path or `--plugins` path that is not a directory (exit 2).
2. **Agent version.** The Claude Code version comes from `--claude-version`, or from `claude --version` (`internal/version`). Unknown is a valid answer; rules then fall back to their version-independent behaviour.
3. **Discovery.** `buildTargets` walks the scan directory (skipping `.git` and `node_modules`) and, with `--user`, the user-scope files under the home directory, collecting the files each supported agent loads (the README lists them agent by agent). `--plugins` adds plugin directories (`cmd/cfgaudit/plugins.go`).
4. **Parsing.** `internal/parser` decodes each file the way its agent does (JSON with comments, TOML, YAML, Markdown with front matter) into a `rules.Target`. A file the agent itself would refuse to load is reported (CFG109) rather than silently dropped.
5. **Rules.** `rules.Run` applies every rule in `rules.All` that passes `--only`/`--skip` and the `.cfgaudit.yml` overrides to each target. Rules are functions from a target to findings; they read parsed values and text and never touch the network or a shell. Two exceptions: CFG013 reads the project's `.gitignore` (through the same scan-root check as every other read), and CFG045 passes command strings to `shellcheck`, only with `--shellcheck`.
6. **Output.** Findings are written as text, a table, JSON, SARIF 2.1.0 or Code Climate JSON, with the OWASP and AVE identifiers attached (`cmd/cfgaudit/avemap.go`).
7. **Exit code.** 1 when an error-severity finding remains (or any finding with `strict`), 0 otherwise, 2 for a usage or config error. `no-exit-codes` in `.cfgaudit.yml` forces 0.

The subcommands `explain` and `list` print rule documentation and the rule list. `init` writes a starter `permissions.deny` list into `.claude/settings.json`, and `policy` keeps the deny rules in `.claude/settings.json` and `.cfgaudit.yml` in step; both write only those files in the directory the user names.

Every read of repository content goes through `internal/scanroot`. A path under the scanned directory whose real location is outside it (a committed symbolic link, or a path through a linked directory) is not opened; it is reported by CFG115. Paths the user names outside the scan (`--user`, `--config`, `--plugins`) are read as given.

The scanner makes no network connections.

## Release pipeline

1. The maintainer tags `vX.Y.Z` on a commit of `main`.
2. `release.yml` and `docker.yml` start. Each first checks that the `CI` workflow passed for exactly that commit and that no earlier run already published it; otherwise nothing is published.
3. They call the reusable workflows `build-release.yml` and `build-image.yml`. Those jobs:
   - run with an egress allowlist (harden-runner `block`), so a compromised build tool cannot send the job's tokens elsewhere;
   - build the archives with GoReleaser and the image with Buildx, with SBOMs from syft;
   - sign SLSA provenance for every archive, `checksums.txt` and the image through GitHub's OIDC token and Sigstore. Because the signer is the reusable workflow and not the tag-triggered one, this is SLSA Build Level 3;
   - publish the GitHub release (with the Sigstore bundle as an asset), the image to ghcr.io (signed with cosign, provenance and SBOM attached as attestations) and the Homebrew cask.
4. The maintainer pushes `main` and the tags to the GitLab copy, whose pipeline publishes the CI/CD Catalog components.

How to verify a download is in the README under [Verifying a release](../README.md#verifying-a-release).

## Attack surface

Every way data or control reaches cfgaudit, and what an attacker controls there:

| Entry point | Who controls it | Exposure |
|---|---|---|
| Files in the scanned directory: JSON (with comments), JSONC, TOML, YAML, Markdown with front matter, `.env`, `.gitignore`, `.claudeignore` | **Attacker** (whoever wrote the repository) | Parsers and rules; crafted structure, size, encoding, invisible characters, symbolic links. Threats 1 to 4 and 7 below. |
| File and directory names in the scanned directory | Attacker | Discovery and the paths quoted in reports. |
| `.cfgaudit.yml` in the scanned directory | Attacker | Can turn rules off or set `no-exit-codes`. cfgaudit announces the file on stderr; a CI job that scans untrusted changes should pass `--config` with its own file. |
| Command-line flags and `--config`, `--plugins`, `--user` paths | User | Trusted. |
| User-scope files (`--user`) | User | Trusted as the user's own configuration. |
| `claude` and `shellcheck` on `PATH` | Whoever controls the machine | Threat 8. |
| Release downloads by the plugin wrapper (`bin/cfgaudit`) | GitHub release assets | Threat 6. |
| CI inputs: pull request contents, `workflow_dispatch` inputs | Contributors, the maintainer | Workflows never interpolate inputs into scripts, validate dispatch inputs (tag and digest formats), and run pull requests with a read-only token and no secrets. |
| Build dependencies: Go modules, actions, base images, CI tools | Their maintainers | Threat 5. |

cfgaudit opens no network connection and no listening socket, so the attack surface of the scanner is the files it reads and the binaries it starts.

## Threat model

Assessed for the scanner and its distribution. Ordered by how likely and how damaging each problem is.

| # | Threat | Impact | Mitigation |
|---|---|---|---|
| 1 | **A false negative**: hostile config that an agent loads and acts on, but no rule flags. | The user trusts a clean report on a dangerous repository. The most likely problem, since agents add configuration surfaces every week. | Rules follow the agents' own loaders and are measured against them; a weekly review of upstream changes; every new rule or surface gets a false-positive run on real repositories before release. The README states that a clean report is not a guarantee. |
| 2 | **The scanner fails open**: a crafted file crashes or hangs cfgaudit, or makes it skip the rest of a scan. | A CI gate passes, or a whole project goes unscanned. | Native Go fuzzing of the parsers, rules and encoders in CI; a file the agent would reject is a finding (CFG109) instead of a scan error; any crash is in scope for a security report. |
| 3 | **Scanned content is executed.** | Arbitrary code execution on the user's machine or CI runner, from simply scanning a repository. | No code path executes, sources or evaluates scanned content. Command strings are matched as text; `--shellcheck` passes them to ShellCheck on stdin, which analyses without running them. gosec and CodeQL check every change. |
| 4 | **Reading outside the scan scope**: a committed symbolic link makes cfgaudit read a file on the scanning machine. | Fragments of that file end up in a report that is uploaded as a CI artifact or SARIF. This happened: up to v1.17.0, parse errors quoted the start of a linked file ([GHSA-x9h6-c6v9-v699](https://github.com/cfgaudit/cfgaudit/security/advisories/GHSA-x9h6-c6v9-v699)). | Since v1.17.1 every read of repository content checks the file's real location (`internal/scanroot`); a link leaving the scan directory is not followed and is reported as [CFG115](rules/CFG115.md). Discovery otherwise reads only the user-scope files with `--user` and paths given explicitly with `--config`/`--plugins`. |
| 5 | **A malicious release**: a compromised dependency, build tool or action alters the binary or the image. | Every user of that release runs attacker code. | Dependency policy in [CONTRIBUTING.md](../CONTRIBUTING.md#dependencies); SHA-pinned actions and digest-pinned images; releases built only from a commit whose CI passed; egress `block` in the build jobs; SLSA Build Level 3 provenance and signatures that users can verify. |
| 6 | **The plugin wrapper downloads a tampered binary.** | Code execution in the user's Claude Code session. | The wrapper downloads over HTTPS, verifies the archive against `checksums.txt`, and `checksums.txt` itself carries signed provenance. |
| 7 | **A secret in a report.** | A credential that cfgaudit found is copied into CI logs or code scanning. | Rule messages name the key and the file, not the secret value. CFG109 quotes the parser's error for a committed file that does not parse, which can include a few characters of that file; the file is in the repository already. |
| 8 | **A tampered `claude` or `shellcheck` on `PATH`.** | Whatever that binary does. | Out of scope: whoever controls `PATH` already controls the machine. Neither is looked up in the scanned repository. `--claude-version` avoids running `claude` at all. |

This assessment is revisited when a feature adds a new actor, a new process cfgaudit starts, or a new release channel.

## Assurance case

The claim: scanning a hostile repository with cfgaudit does not execute its content, does not read or disclose files outside the scanned directory, and does not let it change the result without the user seeing it; and a release that verifies as described in the README was built from this repository by its release workflow. The argument rests on the trust boundary in [SECURITY.md](../SECURITY.md#trust-boundary), the threat model above, the design principles below and the countermeasures for common weaknesses.

### Secure design principles

| Principle | How cfgaudit applies it |
|---|---|
| **Economy of mechanism** | One static binary with two dependencies (`gopkg.in/yaml.v3`, `github.com/BurntSushi/toml`). Rules are plain functions from a parsed target to findings; there is no plugin loading, scripting or network code. |
| **Fail-safe defaults** | A file the agent would refuse to load is a finding (CFG109), not a silent skip. A link leaving the scan directory is not followed (CFG115). The exit code is 1 when an error finding remains; turning that off takes an explicit `no-exit-codes`. |
| **Complete mediation** | Every read of repository content goes through `internal/scanroot`, which checks the file's real location on each read, not once per scan. |
| **Open design** | The source, rules, threat model and release pipeline are public; nothing depends on a secret except the Homebrew tap token, which only publishes the cask. |
| **Separation of privilege** | Releases need a tag on a commit whose CI passed on `main`, and `main` accepts only pull requests that passed the required checks. The build runs in a reusable workflow separate from the tag-triggered one, which is what makes the provenance SLSA Build Level 3. |
| **Least privilege** | The scanner only reads files and writes to stdout. Each workflow job gets the narrowest `GITHUB_TOKEN` permissions it needs, pull request jobs run without secrets, and release jobs can reach only an allowlist of hosts. |
| **Least common mechanism** | Scans share no state: no cache, no daemon, no files written outside the explicit `init` and `policy` subcommands. |
| **Psychological acceptability** | Safe use is the default use: `cfgaudit` in a checkout scans everything it supports. A repository's own `.cfgaudit.yml` is announced on stderr, and the README says how to ignore it with `--config`. |

### Common weaknesses and how they are countered

| Weakness | Where it could arise | Countermeasure |
|---|---|---|
| Path traversal and link following (CWE-22, CWE-59) | Committed symbolic links, linked directories, paths in config values | `internal/scanroot` resolves the real path and refuses anything outside the scan directory; paths found inside config values are matched as text and never opened. |
| OS command and code injection (CWE-78, CWE-94) | Hook commands, MCP server commands, scripts in the repository | Nothing from the repository is executed, sourced or evaluated. The two processes cfgaudit starts have fixed arguments and no shell: `claude --version`, and `shellcheck`, which receives commands on stdin. |
| Memory safety (CWE-787, CWE-125, CWE-416) | Parsers handling crafted input | Go without cgo or `unsafe`. |
| Unsafe deserialization (CWE-502) | JSON, TOML and YAML from the repository | Decoding fills plain maps, slices and structs; no type is chosen by the input and no code runs during decoding. |
| Uncontrolled resource use and crashes (CWE-400, CWE-674) | Deeply nested or malformed files | Native Go fuzzing of parsers, rules and encoders in CI; a crash or hang on any input is in scope for a security report. |
| Exposure of sensitive information (CWE-200, CWE-532) | Secrets that rules detect, reports uploaded as CI artifacts | Rule messages name the key and the file, not the value; files outside the scan directory are not read. |
| Download of code without integrity check (CWE-494) | The plugin wrapper fetching a release | The wrapper verifies the archive against `checksums.txt`, which carries signed provenance. |
| Vulnerable or malicious dependencies (CWE-1395) | Go modules, actions, base images, CI tools | Dependency policy, SHA- and digest-pinned actions and images, Dependabot, govulncheck and dependency review on every pull request, a cooldown before adopting new versions. |

The static analysis that checks these properties on every change is gosec, CodeQL, staticcheck and govulncheck; zizmor checks the workflows.
