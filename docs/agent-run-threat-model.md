# Threat model: running agents against conformance fixtures

Status: decided in #1468, not built. The rules below apply if this is ever reopened.

The file list (`docs/agent-surfaces.yml`) and the source comparison (`check-agent-loaders.yml`) show what cfgaudit claims and what changed upstream. Neither shows what an agent really does with a file. This document decides whether a scheduled job may start a real agent to find out, and under which conditions.

## What is at stake

Starting an agent is different from everything cfgaudit does today. cfgaudit reads files and executes nothing ([design.md](design.md)). An agent binary is third-party code whose purpose is to load configuration and act on it, so a fixture that describes a command can become a process.

| Asset | Why it matters |
|---|---|
| Repository write access and the workflow token | A compromised job could change the repository or a release |
| Release and signing secrets | They must not exist where an agent runs |
| Model or agent credentials | A scheduled job should hold none, and a leaked one costs money or exposes an account |
| Runner network | An agent phoning home turns a fixture into an outbound request |
| Trust in the result | A check that passes without looking gives false confidence |

## Threats

| # | Threat | Mitigation |
|---|---|---|
| 1 | A fixture's hook, MCP server or plugin runs during the observation | Fixtures hold only inert commands, plus a canary that fails the job when it runs (see below) |
| 2 | The observation command itself starts what it lists | Allow a command per agent only after measuring that it starts nothing. See the findings below: this is real |
| 3 | A compromised or updated agent release misbehaves | Pin the version and verify the package hash; no network, no secrets, no token, throwaway container |
| 4 | An agent reaches the network | `--network none`, so a call fails rather than leaves |
| 5 | Output of the agent reaches the workflow | Treat it as untrusted data: no use in an expression, a shell command or an issue title, and only a fixed verdict plus an artifact leave the job |
| 6 | The job needs a login | Out of scope: an agent that cannot start without credentials is not run |
| 7 | The check rots and passes without looking | Each fixture has an expected positive, so an empty listing fails the job |

## The finding that shapes this

"Fixtures are inert" is not enough, because a listing command may execute what it lists:

| Agent | Command | Starts what it lists | Source |
|---|---|---|---|
| Codex 0.166.0 | `codex mcp list --json` | **No.** The fixture server was listed and its command did not run | Measured with an isolated `CODEX_HOME` and a marker file |
| gemini-cli v0.67.0 | `gemini mcp list` | **Yes, in a trusted folder.** It connects to each server, which spawns a stdio command. An untrusted folder skips stdio servers | `packages/cli/src/commands/mcp/list.ts`, `testMCPConnection` |
| OpenCode 1.18.18 | `opencode debug config` | **Yes.** Plugins ran during it, with no prompt and no trust step | Measured for #642, recorded at `openCodeCodeDirs` in `cmd/cfgaudit/main.go` |

So a command must be measured before it is allowed, and the measurement repeats on each pinned version bump, because a later version can change the answer.

Codex also shows that trust belongs to the fixture. Without a trust entry for the project, `codex mcp list` reported no servers at all, so an untrusted run says nothing about the project file. The fixture needs a home directory that marks it as trusted.

## Required controls

Each run:

- runs in a throwaway container, with `--network none`, a read-only root, no capabilities, and non-root
- uses a fresh temporary `HOME` and a fixture from this repository, never a scanned or external repository
- lives in its own workflow with `permissions: {}`, no secrets and no `issues: write`; a second job with `issues: write` reads only a fixed verdict and never runs the agent
- pins the package by version and hash, with a bump reviewed like a dependency
- runs with a time limit
- includes a canary: a fixture entry whose command would write a marker file, and any marker fails the job, reported as a safety failure, not as drift

Never:

- a credential or login of any kind
- a command that sends a model request
- a repository other than the fixtures
- a pull request trigger, so a fixture change cannot run before review

## Decision per agent

| Agent | Proposal | Reason |
|---|---|---|
| Codex | **Run**, as the first agent | Open source, starts without a login, listing measured as not spawning, JSON output |
| gemini-cli | Stay with the source check | The listing spawns servers in a trusted folder, and an untrusted run hides the project file |
| OpenCode | Stay with the source check | The observation runs plugins |
| qwen-code, Kilo | Stay with the source check | Forks of gemini-cli and OpenCode, so assume the same until measured |
| goose | Stay with the source check | Not measured |
| Claude Code, Cursor, Copilot, others | Do not run | Closed source or a login is needed; not measured here, and the source check does not reach them either, which stays a known gap |

## What a first run can and cannot show

With Codex the run can show which project files reach the MCP list, and whether trust and scope behave as `cmd/cfgaudit` assumes. It cannot show hooks, skills or instructions unless a command that lists them is measured the same way. It is one agent and one surface, so its value is a small, safe proof, not coverage.

## Decision

Not built. One agent and one surface do not justify a third-party binary in CI, and the source check costs little. Reopen this only when a loader alert turns out to need a running agent. The per-agent table above stays a proposal for that case.
