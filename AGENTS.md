# Working in cfgaudit

These instructions are for AI coding agents working in this repository. [CONTRIBUTING.md](CONTRIBUTING.md) is the full guide; read *Adding a new rule*, *Engage with the problem, not just the ticket* and *AI-assisted contributions* before you change a rule.

## Working on an issue

Treat the issue as a hypothesis to test, not a spec to fill. cfgaudit's value is precision, so the thinking matters more than the diff.

- Before coding, restate the problem in your own words and check the premise against the primary source: the agent's changelog, its source, or a run of the agent, with the version named. If the premise doesn't hold, say so and propose the correction instead of implementing a rule you've shown to be wrong.
- Hunt the counter-evidence: a realistic benign configuration that trips the change (false positive), the findings a fix could silently drop (must-stay-reported), a simpler or more general approach, and an existing rule or helper that already covers it (`rules/commandsites.go`, the shell word helpers, `instructionSources`).
- For any rule added or changed, measure against real configurations and put the finding delta (added and removed, true and false positives) in the pull request. Don't claim corpus-clean from unit tests.
- Put the reasoning in the pull request: what you considered and rejected, the scope boundary (what it deliberately doesn't report), the tradeoffs. "Implements #N" is not a description.
- Disagreeing with the issue, backed by evidence, is wanted. Raise it on the issue rather than quietly building the wrong thing.
