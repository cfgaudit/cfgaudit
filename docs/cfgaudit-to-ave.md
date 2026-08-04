# cfgaudit ↔ AVE (behavioral crosswalk & gap analysis)

> **Secondary, provisional lens — more provisional than the others.** Mapped against [AVE — Agentic Vulnerability Enumeration](https://github.com/aveproject/ave) (record set **v1.1.0**, 59 records). The [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) stays cfgaudit's **primary** mapping (one risk per rule, in each rule doc and the README).
>
> **Emitted in machine output.** Each mapped rule's primary AVE id — together with its OWASP LLM id — rides in `cfgaudit`'s JSON and SARIF output (`AVEID` in JSON; `properties.ave_id` on the SARIF rule and result, keeping the CFG id as the SARIF `ruleId`). The rule→AVE mapping is a **single file**, [`cmd/cfgaudit/avemap.go`](../cmd/cfgaudit/avemap.go), not a per-rule doc-header line — deliberately, so the whole coupling remains one file to delete if AVE stalls. This crosswalk is the human-readable companion and the source of truth the map is kept in sync with (a consistency test guards against drift). If AVE gains a second independent non-vendor implementation or an OWASP/framework reference, the mapping graduates from "provisional" without structural change.

## What this mapping is — and is not

AVE is a **behavioral** classification standard: each record names a class of malicious agent behavior (a CWE-for-agents), independent of any package or version. cfgaudit is a static auditor of **committed agent-configuration files**. So cfgaudit can only speak to AVE's records flagged `detection_stage: static_detection` (**44 of 59**); the 15 `runtime_observed` records need a running agent and are out of scope by construction, not scored here.

Even within the 44, the boundary is real: cfgaudit does not connect to servers, execute anything, or observe runtime. Where a record needs a live tool manifest, server-side source, or runtime output handling, cfgaudit covers it only if the artifact ships inside a committed `--plugins` package — noted per row.

**This crosswalk reads in both directions.** AVE classes cfgaudit does not yet cover are rule candidates; cfgaudit rules with no AVE class are the reciprocal — the config-surface classes AVE does not yet model.

---

## Coverage (44 `static_detection` records)

| Bucket | Count |
|---|--:|
| Covered — ≥1 CFG rule maps cleanly | 29 |
| Partial — committable slice or adjacent shape only | 11 |
| Gap — committable, no CFG rule (rule candidate) | 4 |
| Out of scope — labelled static by AVE, beyond static-config auditing | 7 |

cfgaudit maps (covered + partial) to **40 of 51**. Counts refreshed 2026-08-04 for the records added since (AVE-2026-00060 through AVE-2026-00070); the four config records among them are all now mapped, AVE-2026-00065 (A2A agent card poisoning) is a new gap, and AVE-2026-00060 (STDIO shell injection) and AVE-2026-00069 (image-hidden instructions in a skill package) join the out-of-scope list as server-source and binary-content analysis respectively. The 5 out-of-scope records are a note back to AVE — see the last section.

---

## Direction 1 — CFG → AVE (covered & partial)

### Instruction / skill content
| CFG | AVE |
|---|---|
| CFG024 hidden Unicode | AVE-2026-00029 homoglyph / Unicode obfuscation |
| CFG026 override / persona / authority · CFG092 Kimi agent file `override: true` (replaces the whole system prompt) | AVE-2026-00007 goal hijack · AVE-2026-00009 jailbreak · AVE-2026-00014 false authority |
| CFG029 bypass permission prompts · CFG091 qwen `approvalMode: yolo` (auto-approves every tool call) | AVE-2026-00012 false permission grant · AVE-2026-00021 autonomous action without confirmation |
| CFG030 conceal behavior | AVE-2026-00010 covert instruction concealment |
| CFG032 pseudo-system / role injection | AVE-2026-00025 conversation-history injection · AVE-2026-00030 false role claim |
| CFG035 configure/trust MCP from instructions | AVE-2026-00011 dynamic tool call *(partial)* · AVE-2026-00034 dynamic skill import *(partial)* |
| CFG036 embedded shell for exfil / auto-exec | AVE-2026-00003 credential exfil · AVE-2026-00013 PII exfil · AVE-2026-00006 crypto drain *(partial)* |
| CFG056 broad / always-on trigger | AVE-2026-00058 deceptive trigger scope · AVE-2026-00038 unbounded tool use *(partial)* · AVE-2026-00022 scope creep *(partial)* |
| CFG057 encoded payload | AVE-2026-00057 obfuscated payload evading scanners · AVE-2026-00026 output-encoding exfil *(partial)* |
| CFG081 survive compaction | AVE-2026-00027 multi-turn instruction persistence |
| CFG090 network reconnaissance | AVE-2026-00032 network-reconnaissance instruction |
| CFG051 / CFG085 delegation & tool grants | AVE-2026-00048 unsafe agent delegation chain |
| CFG031 sensitive path · CFG033 image-exfil sink | AVE-2026-00003 · AVE-2026-00013 · AVE-2026-00039 covert channel *(partial)* |

### Command content
| CFG | AVE |
|---|---|
| CFG008 reverse shell · CFG014 curl\|sh · CFG019 inline script / eval | AVE-2026-00004 shell-pipe code execution · AVE-2026-00033 unsafe deserialization / eval |
| CFG039 rm -rf | AVE-2026-00005 recursive filesystem destruction |
| CFG027 persistence · CFG028 write trust files | AVE-2026-00008 self-replication |
| CFG037 SSH keys · CFG038 env dump · CFG072 DNS exfil | AVE-2026-00003 · AVE-2026-00013 · AVE-2026-00039 |

### MCP configuration
| CFG | AVE |
|---|---|
| CFG007 / CFG050 / CFG054 / CFG065 / CFG073 hardcoded secrets | AVE-2026-00047 hardcoded credentials in component |
| CFG052 name shadowing · CFG059 typosquat | AVE-2026-00017 server impersonation / spoofing |
| CFG019 inline script · CFG020 env code injection · CFG070 repo-relative command | AVE-2026-00055 command execution via untrusted MCP launch config |

**Partial, worth flagging** — AVE-2026-00002 (tool-description injection), AVE-2026-00041 (server-card injection) and AVE-2026-00046 (tool-hook hijack) describe reading a **live** tool manifest or intercepting a running registry. cfgaudit does not connect to servers, so it covers these **only** when the tool description or hook ships in a committed `--plugins` package. For live servers they are behavioral-scanner (SkillSpector / clawscan) territory.

### Config-declared approval, auto-run, pinning and TLS

Added in the 2026-08-04 refresh, against the records AVE shipped from [aveproject/ave#68](https://github.com/aveproject/ave/issues/68), which came out of this crosswalk's own gap list.

| CFG | AVE |
|---|---|
| CFG003 `enableAllProjectMcpServers` · CFG004 `defaultMode` · CFG048 VS Code `chat.permissions.default` · CFG053 blanket MCP-trust keys · CFG063 Codex `approval_policy` / `approvals_reviewer` · CFG079 `autoMode` classifier · CFG087 hook answers a permission gate · CFG091 qwen `approvalMode: yolo` · CFG093 `.cursor/permissions.json` allowlist · CFG096 Gemini MCP `trust` | AVE-2026-00063 approval gate bypassed via declarative configuration |
| CFG047 `.vscode/tasks.json` `folderOpen` + Zed `create_worktree` · CFG086 zero-click hook event · CFG067 committed project hooks | AVE-2026-00064 zero-click code execution via project-load auto-run configuration |
| CFG010 unpinned `@latest`/`:latest` · CFG074 `skills-lock.json` with no integrity pin · CFG055 / CFG089 unpinned marketplace source | AVE-2026-00062 unpinned dependency, supply-chain substitution |
| CFG075 MCP `env`/`args` TLS-verify killswitch | AVE-2026-00061 TLS certificate verification disabled in component configuration |
| CFG097 Gemini remote-agent `auth` literal | AVE-2026-00047 hardcoded credentials in component |

**CFG091 moved.** It was mapped to AVE-2026-00021, whose text reads *"a component that explicitly **instructs** the agent to bypass this confirmation step"*. `tools.approvalMode: "yolo"` is a setting, not an instruction, and AVE-2026-00063 is explicit that it covers the declarative case *"independent of any instruction text"*. AVE-2026-00021 keeps the instruction-driven rules (CFG029).

**Three imperfect fits, stated rather than smoothed over.** CFG067 flags committed hooks on any event, where AVE-2026-00064 is specific to project *load*. CFG055 and CFG089 have two halves each and only the unpinned marketplace source is AVE-2026-00062; the `enabledPlugins` auto-enable half is supply chain more broadly. CFG097 likewise maps on its credential half only: its cleartext `agent_card_url` has **no** AVE class, since AVE-2026-00061 is TLS verification *disabled*, a different failure from no TLS at all.

---

## Direction 2 — AVE gaps → cfgaudit rule candidates

Three `static_detection` classes with no CFG rule today (CFG090 ships AVE-2026-00032; AVE-2026-00036 was implemented as a rule that was reverted after a pre-release FP analysis, and its CFG091 id has since been reused for the qwen approval-mode rule — see below):

| AVE | Status | Note |
|---|---|---|
| **AVE-2026-00036** lateral movement / agent pivot | deferred (the reverted rule; its CFG091 id is now the qwen approvalMode rule) | a pre-release FP analysis found the vocabulary ("lateral movement", "pivot to other systems") is intent-ambiguous — it appears overwhelmingly in security-tool self-description, defensive/detection contexts ("prevent/identify lateral movement"), and offensive-agent capability tables that a static linter cannot distinguish from a malicious directive. Not statically detectable with acceptable precision |
| **AVE-2026-00015** system-prompt extraction | deferred | maps to OWASP LLM07, which cfgaudit treats as runtime — the *leak* is runtime, the *instruction* is static; decide the boundary before filing |
| **AVE-2026-00059** fragmented cross-description injection (ShareLock-class) | deferred | structurally needs multi-source correlation cfgaudit can't do today (every rule checks one file in isolation; the attack's defining property is that no single description is flaggable) — the attack-chain-correlation idea would serve both |

---

## Direction 3 — cfgaudit rules with no AVE class → AVE contribution candidates

AVE's taxonomy is skill/MCP-behavioral and barely models the **agent/IDE configuration surface**. cfgaudit rules cluster into classes AVE does not have:

Status as of 2026-08-04: **four of these eight have shipped** as AVE records, tracked in [aveproject/ave#68](https://github.com/aveproject/ave/issues/68).

| Proposed class | cfgaudit rules | Status |
|---|---|---|
| Zero-click IDE / workspace auto-run | CFG047 (`.vscode/tasks.json` folderOpen), CFG067 (committed `.claude` hooks), CFG086 (Cursor/Copilot zero-click hooks) | **shipped** → AVE-2026-00064 |
| TLS verification disabled in config | CFG075 | **shipped** → AVE-2026-00061 |
| Supply-chain pinning / auto-install | CFG010, CFG055, CFG089, CFG062, CFG074 | **shipped** → AVE-2026-00062 |
| Committed hook auto-approves tool calls | CFG087, CFG088 | **shipped** → AVE-2026-00063 (as the wider "approval gate bypassed by config") |
| Telemetry / context redirect via config | CFG046 (OTEL), CFG005 / CFG071 (base URL) | open — needs distinguishing from AVE-2026-00002's injected-instruction mechanism. Nothing is injected into the model's context here: a committed key/value changes where the process sends data, and detection is a value comparison rather than content analysis |
| Sandbox weakened / disabled in config | CFG022, CFG061, CFG064, CFG079, CFG095 | open |
| Container / daemon posture | CFG082 (`DOCKER_HOST` off-host), CFG084 (`DOCKER_CONTENT_TRUST=0`), CFG083 (Chromium launcher switch) | open — **three** mechanisms with no shared detection logic, not one class |
| MCP network posture | CFG018 (bind-all), CFG066 (wildcard CORS), CFG058 (deprecated SSE), CFG021 (proxy), CFG069 (log redaction) | open — **five** mechanisms, likewise a surface rather than a class |

Two shapes with no class in either direction: a **cleartext** endpoint, distinct from TLS-verification-disabled (CFG049, CFG071, and CFG097's `agent_card_url` half), and **natural-language steering of an approval classifier** (CFG094), which falls between AVE-2026-00063 (excludes instruction text) and AVE-2026-00021 (instructions to the agent, not to a gatekeeper).

Going the other way, **AVE-2026-00065** (A2A agent card poisoning via embedded adversarial instructions) is a class cfgaudit does *not* cover: an inline `agent_card_json` in a `.gemini/agents/*.md` is recognised but its contents are not audited.

The pattern: **AVE models what a malicious skill/server *does*; cfgaudit models what a repository's *config* silently permits.** The two are complementary; the classes above are the clearest contribution direction if AVE wants coverage beyond skill/MCP content.

---

## Note back to AVE — `static_detection` over-includes

Five records carry `detection_stage: static_detection` but are not auditable from committed configuration:

| AVE | Actually requires |
|---|---|
| AVE-2026-00024 content-type mismatch (Magika) | file magic-byte analysis of binaries |
| AVE-2026-00040 insecure output handling | runtime output escaping (OWASP LLM05) |
| AVE-2026-00051 OAuth discovery rebinding | runtime auth-flow redirect |
| AVE-2026-00052 command injection via tool-call parameter | **server-side source** (SAST of the MCP implementation) |
| AVE-2026-00053 path traversal via path parameter | **server-side source** (SAST) |

AVE-2026-00052 / AVE-2026-00053 are server *implementation* flaws, a distinct layer from the rest of AVE. A finer `detection_layer` value (e.g. `server_source`) would let consumers tell config-auditable from SAST-required.

---

*Mappings are class-level behavioral equivalence, not asserted identity. Re-checked against the current AVE record set (up to **AVE-2026-00059** — AVE CHANGELOG **v1.3.0**; note the latest git tag lags at v1.1.0). Unchanged from authoring, so no new behavioral classes to incorporate — this pass only mapped cfgaudit's two new rules: CFG091 (qwen `approvalMode: yolo`) → AVE-2026-00021, CFG092 (Kimi agent `override: true`) → AVE-2026-00007. cfgaudit CFG001–CFG092. Re-check on the next AVE release. A machine-readable form in AVE's own crosswalk schema (`cfgaudit-to-ave.json`) exists for upstream contribution to their `crosswalks/` directory.*
