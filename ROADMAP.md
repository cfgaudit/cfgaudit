# Roadmap

What cfgaudit plans to work on until October 2027. Plans change as the agents change; the [open issues](https://github.com/cfgaudit/cfgaudit/issues) are the current, detailed list. This page is updated when a goal is reached or dropped, and at least once a year.

## Goals

### 1. Follow the agents

Coding agents add configuration surfaces every few weeks: new hook types, new settings that relax a sandbox, new places that load MCP servers or instructions. A file that an agent loads and acts on, but that cfgaudit does not read, is the most likely way for a hostile repository to get past a clean report (threat 1 in [docs/design.md](docs/design.md#threat-model)).

- Keep the weekly review of upstream releases and turn new, committable surfaces into issues within the week.
- Current work: Claude Code settings `env` and hook handlers (#744, #745), GitHub Copilot agent hooks and MCP files (#747), OpenCode 2 (#748), Gemini CLI and Qwen Code (#749, #750), VS Code agent sandbox settings (#751).
- Re-measure every supported agent's loader when it ships a major version, and keep the README's per-agent file lists exact.

### 2. Accurate findings

A false positive costs trust as much as a false negative.

- Fix false positives before new rules (#746).
- Run every new rule and every new scanned surface against real repositories before the release that ships it.
- Keep each rule's documentation in step with the agent versions it describes (#752).

### 3. Findings that tell a story

Several findings that are tolerable one by one can add up to an attack: a broad MCP server, a hook that runs on every prompt and an unpinned package together form a path from a cloned repository to code execution. Planned: a correlation step after the rules that reports such combinations as named attack paths, with the individual findings as evidence. No change to the rule interface is needed.

### 4. Project resilience

- Add a second maintainer with review and merge rights, so that pull requests get a review by someone other than their author and the project continues if one person is unavailable ([GOVERNANCE.md](GOVERNANCE.md#granting-access) says how access is granted).
- Keep the release pipeline at SLSA Build Level 3 with reproducible binaries, and keep the OpenSSF Scorecard and Best Practices results.

## Not planned

- **Running or loading the scanned configuration.** cfgaudit stays a static scanner; it does not start MCP servers, run hooks or contact the network to check a package.
- **Settings that cannot be committed.** Application settings that an agent keeps in its own storage are outside a repository and cannot be audited from one.
- **Agents without a committable, security-relevant configuration file.** Support for a new agent starts with a file in the repository that changes what the agent runs, reads or sends.
