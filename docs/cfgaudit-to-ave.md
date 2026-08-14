# cfgaudit ↔ AVE (behavioral crosswalk & gap analysis)

> **Secondary, provisional lens — more provisional than the others.** Mapped against [AVE — Agentic Vulnerability Enumeration](https://github.com/aveproject/ave) (record set as of 2026-08-14: **77 records**, AVE-2026-00001 through AVE-2026-00077; the latest git tag still reads v1.1.0, which lags the record set). The [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) stays cfgaudit's **primary** mapping (one risk per rule, in each rule doc and the README).
>
> **Emitted in machine output.** Each mapped rule's primary AVE id — together with its OWASP LLM id — rides in `cfgaudit`'s JSON and SARIF output (`AVEID` in JSON; `properties.ave_id` on the SARIF rule and result, keeping the CFG id as the SARIF `ruleId`). The rule→AVE mapping is a **single file**, [`cmd/cfgaudit/avemap.go`](../cmd/cfgaudit/avemap.go), not a per-rule doc-header line — deliberately, so the whole coupling remains one file to delete if AVE stalls. This crosswalk is the human-readable companion and the source of truth the map is kept in sync with (a consistency test guards against drift). If AVE gains a second independent non-vendor implementation or an OWASP/framework reference, the mapping graduates from "provisional" without structural change.

## What this mapping is — and is not

AVE is a **behavioral** classification standard: each record names a class of malicious agent behavior (a CWE-for-agents), independent of any package or version. cfgaudit is a static auditor of **committed agent-configuration files**. So cfgaudit can only speak to AVE's records flagged `detection_stage: static_detection` (**58 of 77**); the 19 `runtime_observed` records need a running agent and are out of scope by construction, not scored here.

Even within the 44, the boundary is real: cfgaudit does not connect to servers, execute anything, or observe runtime. Where a record needs a live tool manifest, server-side source, or runtime output handling, cfgaudit covers it only if the artifact ships inside a committed `--plugins` package — noted per row.

**This crosswalk reads in both directions.** AVE classes cfgaudit does not yet cover are rule candidates; cfgaudit rules with no AVE class are the reciprocal — the config-surface classes AVE does not yet model.

---

## Coverage (58 `static_detection` records)

| Bucket | Count |
|---|--:|
| Covered — ≥1 CFG rule maps cleanly | 33 |
| Partial — committable slice or adjacent shape only | 11 |
| Gap — committable, no CFG rule (rule candidate) | 5 |
| Out of scope — labelled static by AVE, beyond static-config auditing | 9 |

cfgaudit maps (covered + partial) to **44 of 49**. Counts refreshed 2026-08-14 for AVE-2026-00071 through AVE-2026-00077, all seven of them `static_detection`. Four are now covered by rules that had no class before: AVE-2026-00071 (daemon redirect) by CFG082, AVE-2026-00072 (bind-all, which the record also calls NeighborJack) by CFG018, AVE-2026-00073 (endpoint redirect via a static value) by CFG005/CFG046/CFG099, and AVE-2026-00076 (steering an approval classifier) by CFG094. AVE-2026-00077 (cross-origin tool and resource declaration in one MCP manifest) is a new gap. AVE-2026-00074 (reclaimable dead external anchor) and AVE-2026-00075 (`.pyc` bytecode poisoning) join the out-of-scope list: the first needs the anchor resolved over the network, the second is binary-content analysis, and cfgaudit does neither.

The prior pass, 2026-08-04, covered AVE-2026-00060 through AVE-2026-00070: the four config records among them were mapped, AVE-2026-00065 (A2A agent card poisoning) became a gap, and AVE-2026-00060 (STDIO shell injection) and AVE-2026-00069 (image-hidden instructions in a skill package) went out of scope as server-source and binary-content analysis. The out-of-scope records are a note back to AVE — see the last section.

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
| CFG010 unpinned `@latest`/`:latest` · CFG074 `skills-lock.json` with no integrity pin · CFG055 / CFG089 unpinned marketplace source · CFG098 `marketplace.json` archive with no `sha256` | AVE-2026-00062 unpinned dependency, supply-chain substitution |
| CFG075 MCP `env`/`args` TLS-verify killswitch | AVE-2026-00061 TLS certificate verification disabled in component configuration |
| CFG097 Gemini remote-agent `auth` literal | AVE-2026-00047 hardcoded credentials in component |

### Config-declared infrastructure choice

Added in the 2026-08-14 refresh, against AVE-2026-00071 through AVE-2026-00077. Three of these four records ship classes this crosswalk had listed as missing in Direction 3.

| CFG | AVE |
|---|---|
| CFG005 `ANTHROPIC_BASE_URL` · CFG046 OTEL exporter endpoint · CFG099 qwen `proxy` | AVE-2026-00073 telemetry or API endpoint redirect via static configuration value |
| CFG082 `DOCKER_HOST` / `docker -H` | AVE-2026-00071 container daemon redirect, operations land on attacker infrastructure |
| CFG018 MCP server binds to all interfaces | AVE-2026-00072 bind-all with no authentication step (NeighborJack) |
| CFG094 `.cursor/permissions.json` `autoRun.allow_instructions` | AVE-2026-00076 natural-language steering of an approval classifier subagent |

**CFG091 moved.** It was mapped to AVE-2026-00021, whose text reads *"a component that explicitly **instructs** the agent to bypass this confirmation step"*. `tools.approvalMode: "yolo"` is a setting, not an instruction, and AVE-2026-00063 is explicit that it covers the declarative case *"independent of any instruction text"*. AVE-2026-00021 keeps the instruction-driven rules (CFG029).

**Four imperfect fits, stated rather than smoothed over.** CFG067 flags committed hooks on any event, where AVE-2026-00064 is specific to project *load*. CFG055 and CFG089 have two halves each and only the unpinned marketplace source is AVE-2026-00062; the `enabledPlugins` auto-enable half is supply chain more broadly. CFG097 likewise maps on its credential half only: its cleartext `agent_card_url` has **no** AVE class, since AVE-2026-00061 is TLS verification *disabled*, a different failure from no TLS at all. CFG099 has three halves and maps on `proxy` alone: its unconfirmed auto-skill half belongs to AVE-2026-00063, and its `sandboxImage` half has no class, since AVE-2026-00062 is about a version left unpinned rather than an execution image chosen outright.

**Three rules deliberately left unmapped**, recorded here so the decision is not re-made every release:

| CFG | Why no class |
|---|---|
| CFG100 Grok `[plugins]` `enabled` / `paths` | AVE-2026-00064 would be the candidate, but it requires that the loader runs plugin code at project load with no prompt, which is unverified for Grok. The `enabled` half is besides the same wider supply-chain shape CFG055 and CFG089 already sit outside the map for |
| CFG101 deny rule walked past by flag reordering | An ineffective guardrail rather than an attacker behaviour. AVE-2026-00063 is a flag that *removes* a gate; AVE-2026-00068 is composition through shared shell state. Neither is "the denylist misses an equivalent spelling of the same flags" |
| CFG102 two committed skills claiming one name | Name shadowing, but AVE-2026-00017 is explicitly MCP *server* identity and AVE-2026-00066 is registry squatting on names a model hallucinates. A local collision where load order silently picks the winner is neither |

---

## Direction 2 — AVE gaps → cfgaudit rule candidates

Four `static_detection` classes with no CFG rule today (CFG090 ships AVE-2026-00032; AVE-2026-00036 was implemented as a rule that was reverted after a pre-release FP analysis, and its CFG091 id has since been reused for the qwen approval-mode rule — see below):

| AVE | Status | Note |
|---|---|---|
| **AVE-2026-00036** lateral movement / agent pivot | deferred (the reverted rule; its CFG091 id is now the qwen approvalMode rule) | a pre-release FP analysis found the vocabulary ("lateral movement", "pivot to other systems") is intent-ambiguous — it appears overwhelmingly in security-tool self-description, defensive/detection contexts ("prevent/identify lateral movement"), and offensive-agent capability tables that a static linter cannot distinguish from a malicious directive. Not statically detectable with acceptable precision |
| **AVE-2026-00015** system-prompt extraction | deferred | maps to OWASP LLM07, which cfgaudit treats as runtime — the *leak* is runtime, the *instruction* is static; decide the boundary before filing |
| **AVE-2026-00059** fragmented cross-description injection (ShareLock-class) | deferred | structurally needs multi-source correlation cfgaudit can't do today (every rule checks one file in isolation; the attack's defining property is that no single description is flaggable) — the attack-chain-correlation idea would serve both |
| **AVE-2026-00077** cross-origin tool and resource declaration in one MCP server manifest | open (new 2026-08-14) | committable and checkable: the URLs live in a manifest cfgaudit already parses, and the test is whether they resolve to more than one root domain. The nearest existing rule, CFG066, is wildcard CORS, a different question |

---

## Direction 3 — cfgaudit rules with no AVE class → AVE contribution candidates

AVE's taxonomy is skill/MCP-behavioral and barely models the **agent/IDE configuration surface**. cfgaudit rules cluster into classes AVE does not have:

Status as of 2026-08-14: **seven of these eight have shipped** as AVE records, three of them since the 2026-08-04 pass, tracked in [aveproject/ave#68](https://github.com/aveproject/ave/issues/68). Two of the three shipped only the single mechanism cfgaudit could name concretely, not the whole surface it was proposed as.

| Proposed class | cfgaudit rules | Status |
|---|---|---|
| Zero-click IDE / workspace auto-run | CFG047 (`.vscode/tasks.json` folderOpen), CFG067 (committed `.claude` hooks), CFG086 (Cursor/Copilot zero-click hooks) | **shipped** → AVE-2026-00064 |
| TLS verification disabled in config | CFG075 | **shipped** → AVE-2026-00061 |
| Supply-chain pinning / auto-install | CFG010, CFG055, CFG089, CFG062, CFG074 | **shipped** → AVE-2026-00062 |
| Committed hook auto-approves tool calls | CFG087, CFG088 | **shipped** → AVE-2026-00063 (as the wider "approval gate bypassed by config") |
| Telemetry / context redirect via config | CFG046 (OTEL), CFG005 (base URL), CFG099 (qwen `proxy`) | **shipped** → AVE-2026-00073, which names `OTEL_EXPORTER_OTLP_ENDPOINT` itself and states the distinction this row asked for: nothing is injected into the model's context, so detection is a value comparison rather than content analysis. CFG071 is not in it, being cleartext rather than redirect |
| Sandbox weakened / disabled in config | CFG022, CFG061, CFG064, CFG079, CFG095 | open |
| Container / daemon posture | CFG082 (`DOCKER_HOST` off-host), CFG084 (`DOCKER_CONTENT_TRUST=0`), CFG083 (Chromium launcher switch) | **partially shipped** → AVE-2026-00071 took the `DOCKER_HOST` mechanism (CFG082) alone. The other two remain open, which was the point of the row: **three** mechanisms with no shared detection logic, not one class |
| MCP network posture | CFG018 (bind-all), CFG066 (wildcard CORS), CFG058 (deprecated SSE), CFG021 (proxy), CFG069 (log redaction) | **partially shipped** → AVE-2026-00072 took bind-all (CFG018) alone, under this crosswalk's own NeighborJack name. The other four remain open, likewise a surface rather than a class |

**Natural-language steering of an approval classifier** was the second of two shapes listed here with no class in either direction. It has since shipped as AVE-2026-00076, whose own title places it "distinct from AVE-2026-00021 and AVE-2026-00063", the same two records this crosswalk said CFG094 fell between.

Three shapes still have no class in either direction:

| Shape | cfgaudit rules | Note |
|---|---|---|
| A **cleartext** endpoint, distinct from TLS-verification-disabled | CFG049, CFG071, CFG097's `agent_card_url` half | AVE-2026-00061 is verification *disabled*, which is a different failure from no TLS at all |
| A **deny rule that does not cover what it names**, walked past by an equivalent spelling of the same flags | CFG101 | AVE models what an attacker does; this is a guardrail that does not hold. The nearest records are a flag that removes a gate (00063) and composition through shell state (00068) |
| A **local name collision** where load order silently picks the winner and the loser is never reported | CFG102 | AVE-2026-00017 is MCP server identity and AVE-2026-00066 is squatting on hallucinated names in a public registry. Neither covers two committed skills in one repository claiming one name |

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

*Mappings are class-level behavioral equivalence, not asserted identity. Re-checked 2026-08-14 against the current AVE record set, which now runs to **AVE-2026-00077**; the git tag still reads v1.1.0 and the CHANGELOG's released sections stop at v1.3.0, so the records past 00070 are only visible in `records/`, not in a release. This pass mapped one of cfgaudit's five new rules (CFG098 → AVE-2026-00062) and, because seven new records landed, four rules that had no class before: CFG005, CFG046 and CFG099 → AVE-2026-00073; CFG082 → AVE-2026-00071; CFG018 → AVE-2026-00072; CFG094 → AVE-2026-00076. CFG100, CFG101 and CFG102 are deliberately unmapped, with reasons in Direction 1, and the last two are reported back as gaps. cfgaudit CFG001–CFG102. Re-check on the next AVE release. A machine-readable form in AVE's own crosswalk schema (`cfgaudit-to-ave.json`) exists for upstream contribution to their `crosswalks/` directory.*
