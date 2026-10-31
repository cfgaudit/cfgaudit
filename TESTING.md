# Testing cfgaudit

cfgaudit decides what a review of an AI agent's configuration reports, so a wrong answer costs in both directions: a false positive teaches people to skip the scan, and a missed finding gives false confidence. This page is the map of how cfgaudit is tested and what each layer protects against. How to run the tests is in [CONTRIBUTING.md](CONTRIBUTING.md#test-loop); the steps around a release are in [RELEASING.md](RELEASING.md).

## Principles

- **Every bug leaves a test behind.** A fix comes with a test that fails without it. A false positive becomes a case the rule must stay silent on, a missed finding a case it must report, and a crash found by fuzzing a seed input.
- **The agent is the reference.** What an agent loads, ignores or rejects is measured on the agent itself (a run of the released version, its source, or its changelog), not assumed. The measured behavior goes into the tests, for example how Claude Code treats a settings file with a BOM, comments or duplicate keys (#1040 to #1042).
- **Scan what the agent loads, and nothing else.** Discovery follows the agent's own loader, so cfgaudit does not report a file the agent never reads. Tests cover both sides: the file that is loaded and the one next to it that is not.
- **Real configurations decide.** Crafted fixtures show that a rule fires; only real repositories show what else it fires on. Every new rule and every newly scanned surface is run against public repositories before it is released.
- **All platforms count the same.** Path handling, line endings and file permissions differ, so the suite runs on Linux, macOS and Windows.

## Layers

Each layer names what it protects against and when it runs, grouped by what it checks: [findings](#findings), [reports](#reports), [robustness and performance](#robustness-and-performance), [code health](#code-health), [supply chain and repository security](#supply-chain-and-repository-security), [packages and integrations](#packages-and-integrations), [documentation](#documentation), the checks [before each release](#before-each-release) and the [scheduled watches](#scheduled-watches).

### Findings

Whether cfgaudit reports the right findings, and only those.

| Layer | Protects against | Runs |
|---|---|---|
| Rule unit tests (`rules/cfgNNN_test.go`) | wrong findings, severities or messages; missed edge cases; findings where the rule must stay silent | every pull request |
| CLI tests through `run()` (`cmd/cfgaudit/run_test.go` and neighbors) | wrong exit codes, flags that are ignored or conflict, discovery and output format mistakes | every pull request |
| Consistency tests (`rules/consistency_test.go`) | a rule without a docs page, README row or OWASP mapping; severities or OWASP categories that differ between code, docs page and README; mapping tables that name rules that do not exist | every pull request |
| Doc trigger examples (`cmd/cfgaudit/triggerexamples_test.go`) | a rule change that leaves the example in its docs page behind, so the docs show a case the rule no longer reports | every pull request |
| Fixtures (`testdata/settings/valid`, `testdata/settings/invalid`) | a rule that fires on a clean, realistic settings file; an invalid fixture that no longer triggers the rule it is named for | every pull request |
| SchemaStore validation of the fixtures (`schema-validation.yml`) | fixtures that Claude Code's published settings schema rejects, so tests pass on input no user can write; nightly, it opens an issue when the upstream schema drifts | pull requests touching the fixtures, `main`, nightly |
| Metamorphic test (`cmd/cfgaudit/metamorphic_test.go`) | a rule that matches on how a file is written instead of what it says: every doc trigger example and invalid fixture is rewritten (CRLF line endings, minified, tab-indented, keys in reverse order, letters as `\u` escapes, a BOM on Claude Code settings) and must give the same findings | every pull request |

### Reports

Whether the output stays readable for the tools that consume it, and existing findings keep their identity.

| Layer | Protects against | Runs |
|---|---|---|
| Report goldens and schemas (`cmd/cfgaudit/reports_golden_test.go`, `schema-validation.yml`) | a SARIF or Code Climate report that GitHub code scanning or GitLab rejects or reads only in part; an unnoticed change to either format, including the Code Climate fingerprints that identify a finding across runs (#1064) | every pull request; schema validation when the goldens or schemas change |

### Robustness and performance

| Layer | Protects against | Runs |
|---|---|---|
| Fuzzing (`fuzz.yml`): whole scan, path parsers, JSONC stripping, Markdown instructions, key location, prefilters | crashes and hangs on broken or hostile input | short runs on pull requests and `main`, 10 minutes per target weekly |
| Race detector, Linux, macOS and Windows; the tests also run on Windows on ARM, where Go has no race detector | data races between rules running in parallel, platform-specific path and permission bugs | every pull request |
| Linear scaling (`rules/scaling_test.go`): every rule on generated inputs of n and 8·n instruction lines, permission entries, MCP servers and hook commands (`internal/benchcorpus`) | a rule whose allocations or run time grow faster than its input, such as a nested loop over the servers of one file, which a fixed-size benchmark corpus does not show | every pull request |
| Benchmarks (`bench.yml`), pull request against its base | allocation regressions beyond the limit (a gate); time is reported, history is recorded on `main` ([benchmarks page](https://cfgaudit.github.io/benchmarks/)) | pull requests; `main` |

### Code health

| Layer | Protects against | Runs |
|---|---|---|
| Coverage: statement coverage floor (90%) and branch coverage floor (80%) | code that no test exercises | every pull request |
| Unreachable code: `deadcode` from `cmd/cfgaudit`, against the allowlist `.github/deadcode-allow.txt` (golangci-lint's `unused` covers unexported code) | exported functions nothing calls any more, such as a helper only tests still use after a refactor, so the tests check a path production does not take; allowlist entries that went stale | every pull request |
| Static analysis: golangci-lint (with gosec), CodeQL | bugs and insecure patterns in cfgaudit's own code | every pull request; CodeQL also weekly |

### Supply chain and repository security

Whether cfgaudit's own dependencies, workflows and releases can be trusted.

| Layer | Protects against | Runs |
|---|---|---|
| Dependency checks: govulncheck, dependency review; Dependabot security alerts | a known vulnerability in a Go module or a CI tool | every pull request and push; alerts when an advisory is published |
| Workflow security: zizmor, pinact, and the released cfgaudit on the repository's own agent configuration and plugin | injection, excessive permissions and unpinned actions in the workflows; a version comment that does not match its pinned SHA; a weakened rule passing its own check | every pull request |
| Sensitive paths gate | an unreviewed change to files that reach plugin and Action users, the release build or a maintainer's agent setup; the check fails until a maintainer sets the `sensitive-paths-reviewed` label, and a push that changes the pull request's diff on those paths removes it (`sensitivepaths_test.go` covers the comparison) | every pull request |
| Version pins (`pins_test.go`): `bin/cfgaudit`, `.claude-plugin/plugin.json`, the image in `action.yml`, both GitLab component templates and the component examples in the README and docs name the same version | a release pull request that misses a pin, so the Action, the plugin or a GitLab component runs an older release than the one tagged | every pull request |
| Reproducible build (`reproducible-build.yml`): the release archives built with the release's GoReleaser config on an amd64 and an arm64 runner, checksums compared | a release archive that differs from what its tagged source builds, so a download cannot be checked against the source | pull requests that change the build configuration, `go.mod`, `go.sum` or `cmd/` (tests excluded); every push to `main` |
| Docker build, hadolint, dockle | an image that does not build or does not ship ShellCheck for CFG045, Dockerfile mistakes, an image that runs as root | every pull request |
| REUSE | a file without copyright and license information | every pull request |
| OpenSSF Scorecard | a regression in the repository's supply-chain practices, reported as a code scanning alert | weekly and on pushes to `main` |

### Packages and integrations

| Layer | Protects against | Runs |
|---|---|---|
| Action smoke test | an `action.yml` that does not run, writes no valid SARIF, reads the scanned project's own config when a separate one is given, or passes a tool error in advisory mode | every pull request |
| Package smoke tests (`release-smoke.yml`, `pypi.yml`, a step in `build-image.yml`, all through `.github/scripts/smoke-test.sh`) | an archive, wheel or image that does not start, reports the wrong version or finds nothing: each archive is unpacked and run on its platform (Linux amd64 and arm64, macOS arm64, Windows amd64 and arm64), each wheel is installed into a fresh virtual environment on its platform (also musl in Alpine) before upload, the image is run before it is pushed | before every release and PyPI upload; on pull requests that change the release build or the packaging |

### Documentation

| Layer | Protects against | Runs |
|---|---|---|
| Link check | dead links in the README and docs | pull requests touching Markdown, weekly |
| Markdown lint (`markdown.yml`, markdownlint-cli2 with rules on structure and rendering only, see `.markdownlint-cli2.jsonc`); no inline HTML in `docs/rules/`, which the website drops (`.markdownlint-site.jsonc`) | tables that split into the wrong cells, lists and code blocks glued to a paragraph, code blocks without a language, skipped heading levels, broken in-page links; text such as `<verb>` that silently vanishes from cfgaudit.github.io | pull requests and pushes to `main` that change Markdown |

### Before each release

Manual checks a maintainer runs before tagging, see [RELEASING.md](RELEASING.md#before-the-release).

| Layer | Protects against | Runs |
|---|---|---|
| False-positive run on real repositories | findings that crafted fixtures don't show | before each release |
| Precision of new and changed rules: 20 random findings from different repositories judged in context, the rule's premise checked against a primary source (50 findings for a rule a publication quotes) | a rule that matches what its page says while the page is wrong, such as a premise the agent already handles | before each release |
| Documentation review: the README, the pages in `docs/` and the project documents (CONTRIBUTING, SECURITY, TESTING, GOVERNANCE, RELEASING, ROADMAP, `docs/design.md`) checked against the code, the workflows and the repository settings, with AI assistance; a maintainer verifies every reported mismatch | documentation that describes behavior, checks, access or steps that no longer match the project | before each release |

### Scheduled watches

Scheduled jobs watch what cfgaudit depends on from outside and open an issue when something drifts: new versions of the OWASP frameworks the rules map to (`check-framework-versions.yml`), AVE records that the mapping cites (`check-ave-ids.yml`), the MCP reference servers behind CFG059's allowlist (`check-typosquat-allowlist.yml`), and Claude Code's published settings schema (the nightly SchemaStore validation above).

## Adding a rule

A new rule needs unit tests for what it reports and for the cases it must stay silent on, a docs page with a trigger example that the doc test runs (the metamorphic test then rewrites that example without extra work), and a real-repository false-positive run before it is released. Check first whether an existing rule fits. The steps are in [Adding a new rule](CONTRIBUTING.md#adding-a-new-rule).
