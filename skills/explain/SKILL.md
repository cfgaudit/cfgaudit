---
name: explain
description: Explain a cfgaudit rule (what it checks, why, and how to fix it)
disable-model-invocation: true
---

The user wants to understand a cfgaudit rule, usually one a scan just reported.

If the user provided a rule ID (e.g. CFG036), run:

```
cfgaudit explain CFG036
```

Substitute the rule ID the user gave. Present the rendered rule doc — what cfgaudit checks, why it matters, the OWASP mapping, and the safe alternative — and offer concrete remediation for the user's project.

If no rule ID was provided, run `cfgaudit list` and show the available rules so the user can pick one.
