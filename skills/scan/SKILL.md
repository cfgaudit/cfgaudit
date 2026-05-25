---
name: scan
description: Run cfgaudit to scan this project's AI-agent configuration files for security issues
disable-model-invocation: true
---

Run cfgaudit against the current project and report the findings to the user:

```
cfgaudit .
```

This scans settings.json, CLAUDE.md and other instruction files, MCP configs, and .vscode workspace files for prompt injection, dangerous permissions, credential exposure, and related misconfigurations. Each finding is mapped to an OWASP LLM Top 10 risk; explain any findings and how to remediate them.
