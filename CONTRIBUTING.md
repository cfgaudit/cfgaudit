# Contributing to cfgaudit

cfgaudit is a small Go CLI that audits AI-agent configuration files (`settings.json`, MCP configs, hooks, …). This document covers local setup, the test loop, and the step-by-step recipe for adding a new rule.

---

## Development environment

- **Go**: 1.24 or newer (the project pins `go 1.24.3` in `go.mod`).
- **Optional**: Docker (for the release image), `zizmor` for workflow linting, `ajv-cli` if you want to run the SchemaStore fixture validator locally.

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
- Schema validation of `testdata/settings/valid/*.json` against the live SchemaStore schema (push, PR, and nightly)

If you change anything under `.github/workflows/`, run `zizmor .github/workflows/` locally — actions must be pinned to commit SHAs and `persist-credentials: false` must stay on `actions/checkout`.

---

## Adding a new rule

The repo has a few cross-cutting checks (`rules/consistency_test.go`, `rules/fixtures_test.go`) that fail fast if any step below is skipped — follow them in order and the tests will keep you honest.

### 1. Pick the ID

Use the next free `CFG###` identifier (currently `CFG013` is next). Open an issue describing the rule, severity, and which OWASP LLM Top 10 category it falls under.

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
