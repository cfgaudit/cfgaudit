# cfgaudit ↔ OWASP AISVS 1.01 (secondary mapping)

> **Secondary, provisional lens.** Mapped against the [OWASP AI Security Verification Standard (AISVS) **1.01**](https://owasp.org/projects/artificial-intelligence-security-verification-standard-aisvs-docs) (source: [OWASP/AISVS `1.01/en`](https://github.com/OWASP/AISVS/tree/master/1.01/en), read at `55dc220`, 2026-10-08). The [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) stays cfgaudit's **primary** mapping (one risk per rule, in each rule doc and the README). This AISVS view is a complementary lens for teams who verify against AISVS.

## What this mapping is, and what it is not

AISVS verifies a **whole AI system at runtime** ("*Verify that* the system does X"). cfgaudit is a static auditor of **committed agent-configuration files** (Claude Code `settings.json` / `CLAUDE.md` / `.mcp.json` / hooks / plugins, and the cross-agent equivalents). So cfgaudit **contributes static-configuration evidence toward** a subset of AISVS requirements; it does not, by itself, *satisfy* them. Where a requirement needs runtime enforcement, cryptographic identity, hardware attestation, or model/dataset provenance, cfgaudit is out of scope and says so below. Each row cites the requirement by its 1.01 number and wording.

AISVS 1.01 has twelve chapters. The overlap is in **C5** (one requirement), **C9** (agentic action) and **C10** (MCP). **C4** and **C6** are adjacent without a requirement match. The other seven chapters are out of scope (table at the end).

### Re-review for 1.01 (#667)

The previous version of this page said "AISVS 1.0" but cited a structure that neither 1.0 nor 1.01 has: C5.4/C5.5, C9.7 to C9.9 and C10.5/C10.6 do not exist, 9.6.3 and 9.6.4 meant something else, and the out-of-scope table listed C13 and C14. It had been written against a pre-1.0 draft. The 1.0 to 1.01 change itself is small for these chapters (C4, C5 and C6 unchanged apart from reference links; C9 adds 9.2.11, 9.3.9 and 9.5.7 and tightens eight texts toward "enforced by the runtime"; C10 removes 10.2.6, adds seventeen runtime requirements and raises 10.3.3 to level 1), so every row below was remapped against the 1.01 text rather than carried over.

---

## C5: Access Control & Identity

| AISVS requirement | cfgaudit (config-layer evidence) |
|---|---|
| **5.2.5** The policy decision point for agent authorization is isolated from the agent's execution environment. | **CFG028** (a command writes to the agent's own trust/config file, which puts the policy within the agent's reach), and the rules that flag permission policy written into instruction text instead of configuration: **CFG026**, **CFG029**, **CFG035**. |

**Not mapped in C5:** 5.2.1 (allow-lists and default-deny on AI *resources*: datasets, endpoints, vector collections) is adjacent to cfgaudit's permission rules but concerns data resources, not the agent's tool permissions, which C9.5.1 covers. The rest of C5 is authentication, retrieval authorization, multi-tenant isolation and just-in-time privilege at runtime.

## C9: Orchestration & Agentic Action

The strongest overlap. cfgaudit's reason for existing, keeping agent **action policy** in auditable config rather than natural-language prompts and preserving the human approval step, lines up with several C9 requirements.

| AISVS requirement | cfgaudit (config-layer evidence) |
|---|---|
| **9.2.1** The agent runtime blocks privileged or irreversible actions until explicit human approval is received. | **CFG004** (`bypassPermissions` / `auto` default mode), **CFG029** (instruction text: "always approve", "without asking"), **CFG047** (a committed task auto-runs on folder open), **CFG048** (blanket tool auto-approve in `.vscode/settings.json`). Each removes the approval step. |
| **9.2.5** Self-modification (prompt rewriting, tool-list changes, parameter updates) is restricted by boundaries the agent cannot change. | **CFG028** (a command writes to an agent trust/config file), **CFG035** (instruction text tells the agent to configure or trust an MCP server, a tool-list change). |
| **9.2.7** The AI-augmented review of high-risk actions is protected against manipulation and cannot be overridden through prompt injection. | **CFG079** (committed `autoMode` weakens Claude Code's auto-mode classifier), **CFG094** (`.cursor/permissions.json` `autoRun.allow_instructions` steers Cursor's auto-review classifier), **CFG103** (committed Codex config turns off, blunts or rewrites Guardian v2). Each lets the repository write the reviewer's instructions. |
| **9.3.1** Each tool/plugin executes in a least-privilege sandbox or is otherwise isolated. | **CFG022** (Claude Code sandbox weakened or hijacked), **CFG061** (Gemini CLI), **CFG064** (Codex), **CFG095** (Cursor `.cursor/sandbox.json`). |
| **9.3.3** Tool manifests declare required privileges. | **CFG051** (skill/command/subagent `allowed-tools` not over-broad). |
| **9.5.1** Agent actions are authorized against fine-grained policies that restrict which tools an agent may invoke and which parameter values it may supply. | **CFG001/CFG002/CFG023/CFG040** (no unrestricted `allow` entries), **CFG006** (a deny list exists), **CFG041–CFG044** (the deny list covers `.env`, private keys, cloud credentials, SSH keys), **CFG101** (a deny rule that argument reordering walks past), **CFG025** (organisation allow/deny policy), **CFG011** (MCP `alwaysAllow` breadth). |
| **9.5.3** All access control decisions are enforced by application logic or a policy engine, never by the model. | **CFG026/CFG029/CFG035/CFG036**: instruction text that tells the agent to bypass, override, or self-configure trust, which is access-control intent placed where the model decides. |
| **9.5.4** Secrets required at runtime are not exposed in the model's observable context, including system prompts and tool call parameters. | **CFG031** (an instruction file names a secret file), **CFG037/CFG038/CFG078** (commands read or exfiltrate secrets). Adjacent: **CFG007**, **CFG016**, **CFG050/CFG054** (secrets committed to configuration, which is not model context but is where they leak from). |
| **9.5.7** Authority derived through delegation never exceeds the delegating agent's current authority. | **CFG085** (subagent frontmatter sets a weaker permission mode than the session). |

**Out of scope in C9:** execution budgets and kill switches (C9.1, C9.6), approval display, reversibility classification and cryptographic approval binding (9.2.2–9.2.4, 9.2.6, 9.2.8–9.2.11), output schema validation and untrusted-data isolation (9.3.2, 9.3.4–9.3.9), agent identity (C9.4), token propagation, delegation policy and session re-evaluation (9.5.2, 9.5.5, 9.5.6). All are runtime behaviour.

## C10: Model Context Protocol (MCP) Security

Overlaps cfgaudit's MCP-server rules; see also the **[OWASP MCP Top 10 mapping](../README.md#owasp-mcp-top-10-mapping-secondary)** (#173) for the same rules under the MCP-specific taxonomy.

| AISVS requirement | cfgaudit (config-layer evidence) |
|---|---|
| **10.1.1** MCP components are obtained only from trusted sources and cryptographically verified. | **CFG010** (unpinned package or image version), **CFG059** (typosquatted package or endpoint). |
| **10.1.2** Only allow-listed MCP servers are permitted. | **CFG003/CFG053** (blanket approval of every repository server), **CFG052** (a server name shadowed across sources). |
| **10.3.1** Authenticated, encrypted streamable HTTP is used for remote MCP transport. | **CFG049** (remote or cleartext `http://` / `ws://` URL), **CFG058** (deprecated `type: "sse"`). |
| **10.3.3** MCP servers validate the Origin and Host headers to prevent DNS rebinding (level 1 since 1.01). | **CFG017** (`dangerouslyAllowBrowser`, the DNS-rebinding path to the server), **CFG018** (server binds to all interfaces). Server-side requirement; these are the committed settings that widen its exposure. |
| **10.4.7** MCP clients present an explicit consent dialogue upon installation of a local MCP server. | **CFG003/CFG053**: the committed settings that approve every project server and so skip that dialogue. |

**Adjacent, no 1.01 requirement:** hardcoded credentials in MCP `env`/`headers` (**CFG050/CFG054**; C10.2 is now OAuth token handling only), outbound proxy and startup-code injection through a server's environment (**CFG020/CFG021**), and per-tool auto-approval breadth (**CFG011**, mapped under 9.5.1).

**Out of scope in C10:** local-server sandboxing (10.1.3), OAuth 2.1 token validation and binding (C10.2), stdio-only-local, protocol-version floors and mirrored headers (10.3.2, 10.3.4–10.3.6), and schema, payload, caching and elicitation validation (the rest of C10.4). All are runtime protocol behaviour of a server or client.

---

## Adjacent chapters without a requirement match

- **C4: Infrastructure.** 4.1.1 asks that *AI models* execute in isolated sandboxes; the rest is model loading, hardware and edge security. cfgaudit's sandbox rules concern the agent's tool execution and are mapped to 9.3.1.
- **C6: Supply Chain.** Every requirement targets ML model and dataset artifacts (scanning, approved sources, AI BOMs). cfgaudit's configuration-level supply-chain checks (**CFG010**, **CFG055**, **CFG014**) are adjacent and map to 10.1.1 where MCP is concerned.

## Out-of-scope chapters

| Chapter | Why out of scope |
|---|---|
| **C1** Training Data Integrity & Traceability | Training-dataset provenance and poisoning. |
| **C2** Input Validation | Runtime prompt and input handling. |
| **C3** Model Lifecycle Management | Model training, evaluation and deployment lifecycle. |
| **C7** Model Behavior | Runtime model output and behaviour. |
| **C8** Memory, Embeddings & Vector Database | Vector-store and embedding security at runtime. |
| **C11** Adversarial Robustness | Runtime attack resistance. |
| **C12** Monitoring & Logging | Operational telemetry and audit infrastructure. |

## Gap analysis

Walking the in-scope chapters against 1.01, almost every uncovered requirement is runtime, identity, hardware or model/dataset behaviour, outside a static configuration auditor's reach. The configuration-checkable requirements are covered by existing rules. One earlier candidate was implemented: transport restrictions on MCP (now 10.3.1) led to **CFG058**, which keys on `type: "sse"` (#254). The 1.01 additions (9.2.11, 9.3.9, 9.5.7, the C10.2 and C10.4 runtime requirements) brought no new configuration-checkable gap; 9.5.7 maps to an existing rule.
