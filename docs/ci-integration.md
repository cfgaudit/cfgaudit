# CI integration

Running cfgaudit in CI and in your editor: the GitHub Action, the GitLab CI/CD component, the pre-commit hook and the Claude Code plugin.

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

For pull requests, take the config from the base branch so the change cannot rewrite it ([why](usage.md#untrusted-repositories)). A path outside the workspace, such as one under `$RUNNER_TEMP`, is mounted read-only into the scan:

```yaml
- name: cfgaudit config from the base branch
  env:
    BASE_REF: ${{ github.base_ref }}
  run: |
    git fetch --depth=1 origin "$BASE_REF"
    git show FETCH_HEAD:.cfgaudit.yml > "$RUNNER_TEMP/cfgaudit.yml" 2>/dev/null || : > "$RUNNER_TEMP/cfgaudit.yml"
- uses: cfgaudit/cfgaudit@v1
  with:
    config: ${{ runner.temp }}/cfgaudit.yml
```

**Inputs:** `path` (default `.`), `format` (`text`/`json`/`sarif`), `strict`, `user`, `config` (replaces the scanned directory's `.cfgaudit.yml`; relative to the workspace, or an absolute path outside it), `plugins`, `output`, `fail-on` (`error`/`never`), `image`.
**Outputs:** `exit-code`, `output-file`. By default the step fails on findings at or above the configured threshold; set `fail-on: never` for advisory mode. A tool error (exit code 2: a missing path or config, a file that does not parse) fails the step in both modes, because the report is then incomplete.

## GitLab CI/CD component

For GitLab pipelines, include the component (published to the [CI/CD Catalog](https://docs.gitlab.com/ci/components/)):

```yaml
include:
  - component: gitlab.com/cfgaudit/cfgaudit/cfgaudit@v1.19.0
    inputs:
      path: .
      format: text
```

Inputs: `stage`, `path`, `format`, `config`, `version` (pinned ghcr.io image tag, optionally with `@sha256:<digest>`), `allow_failure`. The job fails the pipeline on `error`-severity findings unless `allow_failure: true`. `path` and `config` take path characters and `$VAR` / `${VAR}` references only; quotes, backticks and `$( )` are rejected when the pipeline is created. The output artifact expires after 30 days.

`config` replaces the scanned directory's `.cfgaudit.yml`. For merge requests, keep the config out of the repository, for example in a File-type CI/CD variable, so the merge request cannot change it ([why](usage.md#untrusted-repositories)):

```yaml
include:
  - component: gitlab.com/cfgaudit/cfgaudit/cfgaudit@v1.19.0
    inputs:
      config: $CFGAUDIT_CONFIG     # File-type CI/CD variable holding the .cfgaudit.yml
```

To surface findings **inline in merge requests** via the Code Quality widget, use the second component (emits a GitLab Code Quality report):

```yaml
include:
  - component: gitlab.com/cfgaudit/cfgaudit/cfgaudit-code-quality@v1.19.0
    inputs:
      path: .
```

Pin the component to a released tag, not a moving ref — consistent with cfgaudit's own supply-chain guidance (CFG010/CFG013).

## pre-commit hook

For projects that use the [pre-commit framework](https://pre-commit.com/), add the hook to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/cfgaudit/cfgaudit
    rev: vX.Y.Z  # a release that includes .pre-commit-hooks.yaml (the release after v1.19.0 or later)
    hooks:
      - id: cfgaudit
```

The hook scans the whole repository on every commit: cfgaudit audits a directory, not a list of files, so the hook definition sets `pass_filenames: false` and `always_run: true`. Pin `rev` to a released tag, not a moving ref, as with the GitLab component above. The hook is built from source by pre-commit, so using it requires a Go toolchain. Note that pre-commit builds the hook without the release `-ldflags`, so its output reports `cfgaudit dev` rather than a version number.

## Claude Code plugin

The repo doubles as a Claude Code plugin marketplace. Install it to get an on-demand scan command plus automatic scans when config files change:

```text
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
