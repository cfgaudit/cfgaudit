# cfgaudit ↔ OWASP AISVS 1.0 (secondary mapping)

> **Secondary, provisional lens.** Mapped against the [OWASP AI Security Verification Standard (AISVS) **1.0**](https://owasp.org/www-project-ai-security-verification-standard/) (source: [OWASP/AISVS `1.0/en`](https://github.com/OWASP/AISVS/tree/master/1.0/en)). The [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) stays cfgaudit's **primary** mapping (one risk per rule, in each rule doc and the README). This AISVS view is a complementary lens for teams who verify against AISVS.

## What this mapping is — and is not

AISVS verifies a **whole AI system at runtime** ("*Verify that* the system does X"). cfgaudit is a static auditor of **committed agent-configuration files** (Claude Code `settings.json` / `CLAUDE.md` / `.mcp.json` / hooks / plugins, and the cross-agent equivalents). So cfgaudit **contributes static-configuration evidence toward** a subset of AISVS requirements — it does not, by itself, *satisfy* them. Where a requirement needs runtime enforcement, cryptographic identity, hardware attestation, or model/dataset provenance, cfgaudit is out of scope and says so below.

Only **C4, C5, C6, C9, C10** have any config-layer overlap; the overlap is concentrated in **C9** (agentic action) and **C10** (MCP). The other nine chapters are out of scope (table at the end).

---

## C4 — Infrastructure, Configuration & Deployment

| AISVS requirement | cfgaudit (config-layer evidence) |
|---|---|
| **C4.1** AI Workload Sandboxing & Validation (4.1.1–4.1.2: isolated execution, restricted egress by default) | **CFG022** — flags a `sandbox` config that weakens or hijacks Claude Code's execution sandbox (`excludedCommands` wildcard/shell, attacker-set `bwrapPath`/`socatPath`). Keeps the committed config from disabling the very isolation C4.1 requires. |

**Out of scope in C4:** model-artifact deserialization allowlists & attestation (4.1.3–4.1.7), AI-hardware/GPU/TEE/HSM security (C4.2), edge/distributed-device security (C4.3) — hardware and model-runtime, not committed agent config.

## C5 — Access Control & Identity

cfgaudit audits the Claude Code **permission model**, which is the agent's action-layer access control: an allow/deny list with a default-deny posture. This contributes evidence toward C5.2's *"explicit allow-lists and default-deny policies"* principle, applied to agent tool/command use.

| AISVS requirement | cfgaudit (config-layer evidence) |
|---|---|
| **C5.2** AI Resource Authorization (5.2.1: access controls with explicit allow-lists & default-deny) | **CFG001/CFG002/CFG023/CFG040** (no unrestricted `allow` entries), **CFG004** (no `bypassPermissions`/`auto` default mode), **CFG006** (a non-empty `permissions.deny` exists — default-deny), **CFG041–CFG044** (deny covers credential / private-key / cloud / SSH files), **CFG025** (custom org allow/deny policy is honoured), **CFG048** (no blanket tool auto-approve in `.vscode`). |

**Out of scope in C5:** step-up & federated authentication (C5.1), just-in-time privileged access & data-classification taxonomy/propagation (5.2.2–5.2.4), query-time authorization (C5.3), output-entitlement filtering (C5.4), policy-decision-point isolation (C5.5) — runtime identity & enforcement, not config.

## C6 — Supply Chain

**Adjacent, no direct requirement match.** Every C6 requirement targets **ML model/dataset artifacts** (signed origin records, Trojan-layer scanning, dataset poisoning assessment, AI-BOM / CycloneDX-SPDX) — assets cfgaudit does not audit. cfgaudit's config-layer supply-chain hygiene is conceptually adjacent but does not map to a specific C6 control:

- **CFG010** — MCP server uses an unpinned package/image version (`@latest`, `:latest`).
- **CFG055** — committed settings auto-enable a plugin / register a third-party marketplace (loads third-party hooks/MCP).
- **CFG014** — command pipes `curl`/`wget` straight into a shell (remote code execution).

## C9 — Orchestration & Agentic Action Security

The strongest overlap. cfgaudit's reason for existing — keeping agent **action policy** in auditable config rather than natural-language prompts, and preserving the human-in-the-loop — lines up with several C9 controls.

| AISVS requirement | cfgaudit (config-layer evidence) |
|---|---|
| **C9.2** High-Impact Action Approval (9.2.1: human-approval gate before privileged/irreversible actions) | **CFG004** (`bypassPermissions`/`auto`), **CFG029** (CLAUDE.md "always approve" / "without asking"), **CFG047** (`.vscode` task auto-runs on folder open), **CFG048** (blanket tool auto-approve) — each removes the approval gate; cfgaudit flags them. |
| **C9.3** Component Isolation & Safe Integration (9.3.1 least-privilege; 9.3.5 tool manifests declare privileges) | **CFG022** (sandbox integrity), **CFG051** (skill/command/subagent `allowed-tools` not over-broad — least-privilege manifest), **CFG001/CFG023** (least-privilege command grants). |
| **C9.6.3** Access-control decisions never made by the model; model output cannot override them | **CFG026/CFG029/CFG035/CFG036** — flag CLAUDE.md/injection text that instructs Claude to bypass, override, or self-configure trust. |
| **C9.6.4** Secrets not exposed in the model-observable context | **CFG007** (`env` secret), **CFG016** (credential helper in project settings), **CFG050/CFG054** (MCP `env`/`headers` secret), **CFG031** (instruction names a secret file), **CFG037/CFG038/CFG078** (commands read / exfiltrate secrets). |
| **C9.7.1** Pre-execution gates evaluate actions against deny rules & allow-lists | **CFG006**, **CFG041–CFG044**, **CFG025** (the `permissions.deny` / org-policy a gate consults) + the allow-list-hygiene rules above. |
| **C9.7.3** Writes to persistent external state need approval / policy authorization | **CFG028** (command writes to a Claude trust/config file), **CFG047**, **CFG004**. |
| **C9.9.3** Tool-execution security policy expressed as versioned, machine-interpretable **config — not natural-language prompts** | cfgaudit's core thesis: flags access-control intent smuggled into CLAUDE.md (**CFG029/CFG026/CFG035/CFG036**) and audits the real `permissions` config instead. |

**Out of scope in C9:** execution budgets & circuit breakers (C9.1), cryptographic approval binding (9.2.3), agent identity / signing / tamper-evident audit (C9.4), semantic output validation (C9.5), delegation & continuous re-evaluation (most of C9.6), runtime intent/outcome verification (9.7.2/9.7.4), multi-agent/swarm isolation (C9.8), runtime data-flow graph & origin tracking (9.9.1/9.9.2/9.9.4–9.9.8).

## C10 — Model Context Protocol (MCP) Security

Overlaps cfgaudit's MCP-server rules; see also the **[OWASP MCP Top 10 mapping](../README.md#owasp-mcp-top-10-mapping-secondary)** (#173) for the same rules under the MCP-specific taxonomy.

| AISVS requirement | cfgaudit (config-layer evidence) |
|---|---|
| **C10.1** Component Integrity & Supply-Chain Hygiene (10.1.1 trusted/verified components; 10.1.2 allowlisted server identifiers, reject unlisted) | **CFG010** (unpinned version), **CFG003/CFG053** (no blanket auto-approval of all repo servers), **CFG011** (`alwaysAllow` not over-broad), **CFG052** (server-name shadowing across sources). |
| **C10.2** Authentication & Authorization (secret-hygiene subset) | **CFG050/CFG054** — no hardcoded credentials in MCP `env`/`headers`. |
| **C10.3** Secure Transport & Network Boundary (10.3.1 encrypted transport / SSE restricted; 10.3.3 DNS-rebinding / Origin-Host validation) | **CFG049** (remote/cleartext `http://`/`ws://` MCP URL), **CFG058** (deprecated `type: "sse"` transport — 10.3.1), **CFG017** (`dangerouslyAllowBrowser` → DNS-rebinding to RCE), **CFG018** (binds to all interfaces — NeighborJack). |
| **C10.5.1** Outbound access restricted to approved destinations | **CFG021** (`env` routes traffic through a non-local proxy), **CFG020** (dynamic-linker injection). |
| **C10.6.2** Expose only allow-listed, statically-defined functions | **CFG011** (`alwaysAllow` breadth / least-privilege MCP tools). |

**Out of scope in C10:** OAuth 2.1 token flows & session teardown (most of C10.2), protocol-version negotiation & header integrity (10.3.4/10.3.5), tool-response validation & schema-signature provenance (C10.4), fail-closed runtime semantics (C10.6.1) — runtime protocol behaviour, not committed config.

---

## Out-of-scope chapters

These AISVS chapters have no committed-agent-config surface cfgaudit can statically audit — they verify model, data, or runtime behaviour:

| Chapter | Why out of scope |
|---|---|
| **C1** Training Data Integrity & Traceability | Training-dataset provenance/poisoning — no agent config. |
| **C2** Input Validation | Runtime prompt/input handling. |
| **C3** Model Lifecycle Management | Model training/eval/deployment lifecycle. |
| **C7** Model Behavior | Runtime model output/behaviour. |
| **C8** Memory, Embeddings & Vector Database | Vector-store/embedding security at runtime. |
| **C11** Adversarial Robustness | Runtime attack resistance / red-teaming. |
| **C12** Privacy | Data-handling / PII at runtime. |
| **C13** Monitoring & Logging | Operational telemetry/audit infrastructure. |
| **C14** Human Oversight | Operational governance & review processes. |

(The runtime/identity/hardware portions of C4/C5/C6/C9/C10 are out of scope too, as noted per chapter above.)

## Gap analysis (statically-checkable AISVS requirements with no cfgaudit rule yet)

Walking the in-scope chapters, almost every uncovered requirement is **runtime, identity, hardware, or model/dataset** — outside a static config auditor's reach. The genuinely config-checkable requirements are already substantially covered by existing rules. One candidate surfaced and was implemented:

- **C10.3.1 — alternate MCP transports (SSE) restricted to local/controlled use.** cfgaudit's CFG049 flags a *remote/cleartext* MCP URL by scheme and host, but not the deprecated/weaker **`type: "sse"`** transport itself. Now covered by **CFG058**, which keys on the `type` field (statically checkable) — filed as #254, implemented.

No further high-confidence new-rule gaps were found; this is itself a useful result (AISVS's config-checkable surface is largely covered, and the rest is genuinely out of static-config scope).
