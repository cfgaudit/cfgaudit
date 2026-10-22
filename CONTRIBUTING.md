# Contributing to cfgaudit

cfgaudit is a small Go CLI that audits AI-agent configuration files (`settings.json`, MCP configs, hooks, …). This document covers reporting a bug, local setup, the test loop, code review, dependencies, and the step-by-step recipe for adding a new rule. Who maintains the project and holds which access is in [GOVERNANCE.md](GOVERNANCE.md); how cfgaudit is built and what it defends against is in [docs/design.md](docs/design.md). Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md); what is planned is in the [roadmap](ROADMAP.md).

---

## Reporting a bug

Open an issue at https://github.com/cfgaudit/cfgaudit/issues. A missed detection, a finding on config that is fine, a crash or a wrong exit code are all bugs. Please include:

- the cfgaudit version (`cfgaudit --version`) and how you installed it (release binary, `go install`, Homebrew, container image, GitHub Action, GitLab component);
- the command you ran, with its flags, and your `.cfgaudit.yml` if there is one;
- the smallest config file that shows the problem, with real secrets, hostnames and tokens replaced;
- the findings you expected and the findings you got (`--format json` output is easiest to compare).

For a false positive or a missed detection, name the agent and its version (e.g. Claude Code 2.1.x, Codex 0.15x) if the behaviour you expected depends on how that agent loads the file.

Vulnerabilities in cfgaudit itself go through private reporting instead, see [SECURITY.md](SECURITY.md).

---

## Development environment

- **Go**: 1.26 or newer (`go.mod` declares `go 1.26`; CI and releases build with the newest 1.26 patch).
- **Optional**: Docker (for the release image), `zizmor` for workflow linting, Node.js if you want to run the SchemaStore fixture validator locally (`npm ci --prefix .github/tools/ajv`, then `node .github/tools/ajv/validate.js <schema> testdata/settings/valid/*.json`).

Clone and build:

```sh
git clone https://github.com/cfgaudit/cfgaudit
cd cfgaudit
go build ./...
```

Run the CLI against a checked-out repo:

```sh
go run ./cmd/cfgaudit /path/to/project
```

---

## Test loop

```sh
go test ./...                  # unit tests + cross-cutting consistency / fixture tests
go test -run TestCFG001 ./...  # one rule
go vet ./...                   # cheap static check, same one CI runs
```

CI additionally runs:

- `golangci-lint` (latest)
- `govulncheck` against the module
- `zizmor` against `.github/workflows/`
- Branch coverage with `gobco` (see [Tests](#4-tests))
- Schema validation of `testdata/settings/valid/*.json` against the live SchemaStore schema (push, PR, and nightly)

If you change anything under `.github/workflows/`, run `zizmor .github/workflows/` locally — actions must be pinned to commit SHAs and `persist-credentials: false` must stay on `actions/checkout`.

---

## Adding a new rule

The repo has a few cross-cutting checks (`rules/consistency_test.go`, `rules/fixtures_test.go`) that fail fast if any step below is skipped — follow them in order and the tests will keep you honest.

### 1. Pick the ID

Use the next free `CFG###` identifier: one above the highest `rules/cfgNNN.go` (`ls rules/cfg[0-9]*.go | grep -v _test | sort -V | tail -1`). Open an issue describing the rule, severity, and which OWASP LLM Top 10 category it falls under.

### 2. Implement the rule

Create `rules/cfgNNN.go`:

```go
package rules

import "github.com/cfgaudit/cfgaudit/internal/finding"

type cfgNNN struct{}

var CFGNNN = &cfgNNN{}

func init() { All = append(All, CFGNNN) }

func (r *cfgNNN) ID() string { return "CFGNNN" }

func (r *cfgNNN) Check(t *Target) []finding.Finding {
    if t.Settings == nil {
        return nil
    }
    // ... inspect t.Settings, return zero or more findings ...
    return nil
}
```

The `Rule` interface (`rules/rule.go`) is just `ID()` and `Check(*Target)`. Optional interfaces:

- **`Versioned`** — if the rule should only fire on a minimum Claude Code release, add `MinVersion() string` (see `rules/cfg003.go` for an example).
- **User-scope escalation** — append `userScopeNote(t)` to the message; the helper returns a non-empty suffix only when `t.Scope == finding.ScopeUser`. Severity escalation is rule-specific (see `rules/cfg009.go`).

### 3. Use the parser helpers

Available in `internal/parser`:

| Function | Purpose |
|---|---|
| `ParseSettings(path)` | Read and decode a `settings.json` file from disk. |
| `ParseSettingsBytes(data, path)` | Decode an in-memory byte slice (used by tests). |
| `ParseIgnore(path)` | Read a `.claudeignore` file. |
| `HasPattern(lines, pattern)` | Convenience match against `.claudeignore` entries. |

Settings expose typed fields (`Permissions`, `Env`, `Hooks`, `MCPServers`) plus a `Raw map[string]json.RawMessage` for keys cfgaudit does not strictly model. Use the typed fields where possible; fall back to `Raw` for keys the schema knows about but cfgaudit does not.

### 4. Tests

Every change in behaviour comes with tests: a new rule, a new scanned file or surface, a fix, a new flag or output. A fix adds a test that fails without it. A change that only moves code keeps the existing tests passing unchanged. CI fails when total statement coverage drops below the floor in `ci.yml`, or when branch coverage drops below 80%.

Branch coverage is measured with [gobco](https://github.com/rillig/gobco), which counts a branch as covered only when the package's own tests take it. To see the uncovered branches of a package, build gobco from the pinned module and run it on a copy of the checkout with the dependencies vendored (gobco cannot resolve them from the module cache; do not commit the `vendor/` directory):

```sh
(cd .github/tools/gobco && go build -o "$HOME/go/bin/gobco" github.com/rillig/gobco)
git clone --quiet . /tmp/cfgaudit-cov && cd /tmp/cfgaudit-cov && go mod vendor
gobco -branch ./internal/parser   # lists each branch that was never taken, then the total
```

For a rule, that means:

`rules/cfgNNN_test.go`:

```go
func TestCFGNNN_Trigger(t *testing.T) {
    f := CFGNNN.Check(settingsTarget(t, `{"…":…}`))
    if len(f) != 1 || f[0].Severity != finding.Error {
        t.Fatalf("expected 1 error finding, got %+v", f)
    }
}
```

`settingsTarget` (in `rules/cfg001_test.go`) parses JSON via `parser.ParseSettingsBytes` and wraps it in a `Target`. Cover at least one trigger case and the obvious no-finding negatives (rule key absent, settings absent, etc.). If the rule is scope-sensitive, also test `finding.ScopeUser` (see `rules/scope_test.go`).

### 5. Add the docs page

`docs/rules/CFGNNN.md`:

```markdown
# CFGNNN — short title

**Severity:** `error` | `warn` | `info`
**OWASP:** [LLM0X:2025 – Category](https://owasp.org/...)

## What cfgaudit checks
...

## Trigger example
...

## Safe alternative
...

## References
...
```

The consistency test (`rules/consistency_test.go`) requires:

- A doc file at `docs/rules/CFGNNN.md` for every registered rule
- The doc must mention "OWASP" or "LLM"
- The rule must appear in the README's rule table

### 6. Add fixtures

- **Trigger fixture** (required): `testdata/settings/invalid/CFGNNN_<slug>.json`. The cross-cutting test in `rules/fixtures_test.go` derives the expected rule ID from the filename prefix and asserts that the rule fires.
- **Valid fixtures**: every file in `testdata/settings/valid/` must produce **zero** findings across all rules. If your new rule would flag any of `minimal.json`, `full.json`, `team-project.json`, `managed-org.json`, fix the rule or update the fixture.

The schema-validation workflow (`.github/workflows/schema-validation.yml`) validates `valid/*.json` against the upstream Claude Code schema on push and nightly. `invalid/*.json` is only checked for parseable JSON (with `jq empty`), since invalid fixtures are intentionally non-compliant.

### 7. Update the README

Add a row to the rules table in `README.md`:

```markdown
| [CFGNNN](docs/rules/CFGNNN.md) | severity | one-line description | LLM0X |
```

The reverse-consistency test fails if you mention `CFGNNN` in the README without registering a corresponding rule in `All`.

---

## Commit and PR conventions

- **Branch names**: `<type>/<short-slug>`, e.g. `feat/cfg013-…`, `docs/contributing`, `chore/dependabot`, `ci/<name>`. No issue number required, but include it in the PR body via `Closes #N`.
- **Commit messages**: one short imperative line (`feat: add CFG013 rule (...)`). No `Co-Authored-By` trailer.
- **PR body**: short Summary section + Test plan checklist. Note deviations from the issue's acceptance criteria.
- **Merging**: squash-merge, delete branch.

---

## Code review

Every change, including the maintainer's own, lands through a pull request; nothing is pushed to `main` directly.

**How review happens.** The maintainer reviews every pull request from a contributor; a second maintainer reviews the maintainer's once there is one (see [GOVERNANCE.md](GOVERNANCE.md)). Review starts when the required checks pass. Comments go on the pull request, and the author answers each one with a change or a reason.

**What the reviewer checks:**

- **Scope.** The change does what its issue asks and nothing unrelated; a change in behaviour has an issue.
- **Tests.** The tests cover the change, and a fix adds a test that fails without it (see [Tests](#4-tests)). Coverage stays above both floors.
- **Rules.** A new or changed rule has its doc page, fixtures and README row, follows the agent's real loader (measured, not assumed), and its message names keys and files, never a secret value.
- **The trust boundary.** Scanned content is still never executed or evaluated, every read of repository content still goes through `internal/scanroot`, and the scanner opens no network connection. A change that adds a process, a network call or a new kind of input updates [docs/design.md](docs/design.md).
- **Dependencies.** A new or updated dependency follows [Dependencies](#dependencies).
- **Workflows.** Actions are pinned to commit SHAs, permissions are the least the job needs, no input is interpolated into a script, and zizmor passes.
- **Docs and style.** README, rule docs and CONTRIBUTING.md match the change.

**What makes a change acceptable:** all required checks pass, every review comment is resolved, and the title is a conventional commit line that references the issue. The pull request is then squash-merged.

**New contributors** can start with an issue labelled [`good first issue`](https://github.com/cfgaudit/cfgaudit/labels/good%20first%20issue): small, self-contained changes with the expected result spelled out.

---

## Dependencies

cfgaudit keeps its dependencies few, because every one of them runs inside a tool whose input is hostile.

- **Go modules.** Dependencies are declared in `go.mod` and pinned by hash in `go.sum`; CI runs `go mod verify` before building. The binary has two direct dependencies, `gopkg.in/yaml.v3` and `github.com/BurntSushi/toml`, besides the standard library.
- **Adding one.** A new dependency needs a reason in its pull request: what the standard library cannot do, who maintains the module, and how much code it pulls in. A parser for a config format an agent reads is the usual case; a convenience library is not.
- **CI tools and actions.** GitHub Actions are pinned by commit SHA with the version in a comment, container images by digest, and the Python and Node tools CI installs (zizmor, the schema validator) by a hashed lock file under `.github/tools/`.
- **Updates.** Dependabot proposes updates for Go modules, GitHub Actions, Docker images and the pip and npm tool locks, each held back for 7 days after release so a compromised or yanked version is noticed before it lands; security updates skip that wait. Updates go through the same pull request checks as any change.
- **Tracking.** `govulncheck` runs in CI on every pull request and on `main`; Dependabot security alerts and OpenSSF Scorecard cover the rest. Release archives and the container image carry an SBOM listing what went into them.

---

## Repositories

The project lives in three repositories. Only the first takes contributions; the other two are written by the release process.

| Repository | What it is | How it is updated |
|---|---|---|
| [github.com/cfgaudit/cfgaudit](https://github.com/cfgaudit/cfgaudit) | The source, issues, pull requests, releases and the container image. Authoritative. | Pull requests. |
| [github.com/cfgaudit/homebrew-tap](https://github.com/cfgaudit/homebrew-tap) | The Homebrew cask behind `brew install cfgaudit/tap/cfgaudit`. | GoReleaser writes the cask on each release. |
| [gitlab.com/cfgaudit/cfgaudit](https://gitlab.com/cfgaudit/cfgaudit) | A copy of this repository that publishes the GitLab CI/CD Catalog components. | The maintainer pushes `main` and the release tags after each release. |

---

## Project layout reference

```
cmd/cfgaudit/        # CLI entrypoint, output formatters (text/JSON/SARIF), flag parsing
internal/parser/     # settings.json + .claudeignore parsing
internal/finding/    # Finding/Severity/Scope types
internal/version/    # Claude Code version detect + compare
internal/schema/     # bundled SchemaStore schema + lightweight introspection
rules/               # one file per rule + cross-cutting tests + runner
docs/rules/          # one Markdown file per rule
testdata/settings/   # valid/ and invalid/ fixtures (driven by rules/fixtures_test.go)
.github/workflows/   # CI, Docker release, nightly schema validation
```

If something here looks out of date, please send a PR.
