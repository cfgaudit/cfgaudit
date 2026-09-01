package main

import (
	"regexp"

	cfgaudit "github.com/cfgaudit/cfgaudit"
	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// jsonFinding is a finding enriched with its taxonomy ids for machine output.
// The mapping is rule-level, so the ids are resolved by RuleID at serialization
// time rather than stored on finding.Finding — the core finding type stays
// unchanged and the text/table output is untouched. Both fields are omitempty:
// every rule has an OWASP id, but only the ~53 rules in aveByRule carry an AVE
// id, and a new rule for a threat AVE has not catalogued carries none.
type jsonFinding struct {
	finding.Finding
	OWASP string `json:"OWASP,omitempty"`
	AVEID string `json:"AVEID,omitempty"`
}

// withTaxonomy wraps each finding with its OWASP LLM and AVE ids for JSON output.
func withTaxonomy(findings []finding.Finding) []jsonFinding {
	out := make([]jsonFinding, len(findings))
	for i, f := range findings {
		out[i] = jsonFinding{Finding: f, OWASP: ruleOWASP(f.RuleID), AVEID: ruleAVE(f.RuleID)}
	}
	return out
}

// aveByRule maps a cfgaudit rule to its primary AVE behavioral class
// (Agentic Vulnerability Enumeration, https://github.com/aveproject/ave). It is
// deliberately a single file rather than a per-rule doc-header line: AVE is early
// and single-vendor, and the whole mapping is meant to be removable (see
// docs/cfgaudit-to-ave.md) — deleting one file reverses it, where scattering the
// id across 53 doc headers would not. The primary ids here are sourced from the
// mappings in docs/cfgaudit-to-ave.md; a rule may cover more than one AVE class,
// but only the canonical one is emitted so the output field stays singular
// (matching AVE's own one-ruleId-per-class SARIF model).
//
// OWASP LLM ids are NOT here — they are intrinsic to every rule and parsed from
// the `**OWASP:**` doc header (see ruleOWASP), the existing single source of
// truth used by `cfgaudit list`.
var aveByRule = map[string]string{
	// instruction / skill content
	"CFG024": "AVE-2026-00029", // hidden Unicode → homoglyph/unicode obfuscation
	"CFG026": "AVE-2026-00007", // override/persona → goal hijack
	"CFG092": "AVE-2026-00007", // Kimi agent override: true replaces the whole system prompt → goal hijack
	"CFG029": "AVE-2026-00021", // bypass prompts → autonomous action without confirmation
	"CFG030": "AVE-2026-00010", // conceal behavior → covert instruction concealment
	"CFG031": "AVE-2026-00003", // sensitive path → credential exfil
	"CFG032": "AVE-2026-00025", // pseudo-system/role injection → conversation-history injection
	"CFG033": "AVE-2026-00039", // image-exfil sink → covert channel
	"CFG035": "AVE-2026-00011", // configure/trust MCP → dynamic tool call
	"CFG036": "AVE-2026-00003", // embedded exfil shell → credential exfil
	"CFG051": "AVE-2026-00048", // allowed-tools grant → unsafe delegation
	"CFG056": "AVE-2026-00058", // broad trigger → deceptive trigger scope
	"CFG057": "AVE-2026-00057", // encoded payload → obfuscated payload
	"CFG081": "AVE-2026-00027", // survive compaction → multi-turn persistence
	"CFG085": "AVE-2026-00048", // subagent perm mode → unsafe delegation
	"CFG090": "AVE-2026-00032", // network reconnaissance instruction

	// command content
	"CFG008": "AVE-2026-00004", // reverse shell → shell-pipe code execution
	"CFG014": "AVE-2026-00004", // curl|sh → shell-pipe code execution
	"CFG027": "AVE-2026-00008", // persistence → self-replication
	"CFG028": "AVE-2026-00008", // write trust files → self-replication
	"CFG037": "AVE-2026-00003", // SSH key read → credential exfil
	"CFG038": "AVE-2026-00003", // env dump → credential exfil
	"CFG039": "AVE-2026-00005", // rm -rf → recursive filesystem destruction
	"CFG072": "AVE-2026-00039", // DNS exfil → covert channel

	// MCP configuration
	"CFG007": "AVE-2026-00047", // settings secret → hardcoded credentials
	"CFG050": "AVE-2026-00047", // MCP env/headers secret → hardcoded credentials
	"CFG054": "AVE-2026-00047", // entropy secret → hardcoded credentials
	"CFG065": "AVE-2026-00047", // Continue inline apiKey → hardcoded credentials
	"CFG073": "AVE-2026-00047", // crypto signing key → hardcoded credentials
	"CFG052": "AVE-2026-00017", // name shadowing → server impersonation
	"CFG059": "AVE-2026-00017", // typosquat → server impersonation
	"CFG019": "AVE-2026-00055", // MCP inline script → untrusted launch config command exec
	"CFG020": "AVE-2026-00055", // MCP env code injection → untrusted launch config command exec
	"CFG070": "AVE-2026-00055", // MCP repo-relative command → untrusted launch config command exec

	// Approval gate bypassed by declarative configuration (AVE-2026-00063).
	// The record is explicit that it is "distinct from AVE-2026-00048" and
	// "independent of any instruction text": a config flag that removes a
	// human-approval step, not an instruction that talks the agent out of one.
	// That line is why CFG091 sits here rather than under 00021 (which reads "a
	// component that explicitly INSTRUCTS the agent to bypass this confirmation
	// step") — approvalMode: yolo is a setting, not an instruction.
	"CFG003": "AVE-2026-00063", // enableAllProjectMcpServers → every repo MCP server auto-approved
	"CFG004": "AVE-2026-00063", // defaultMode bypassPermissions/auto
	"CFG048": "AVE-2026-00063", // VS Code chat.permissions.default autoApprove/autopilot, terminal autoApprove
	"CFG053": "AVE-2026-00063", // blanket MCP-trust keys (allowAllClaudeAiMcps, enabledMcpjsonServers "*")
	"CFG063": "AVE-2026-00063", // Codex approval_policy never / approvals_reviewer auto_review
	"CFG079": "AVE-2026-00063", // autoMode classifier weakened by config
	"CFG087": "AVE-2026-00063", // committed hook answers a permission gate with the allowing value
	"CFG091": "AVE-2026-00063", // qwen tools.approvalMode: yolo
	"CFG093": "AVE-2026-00063", // committed .cursor/permissions.json allowlist
	"CFG096": "AVE-2026-00063", // Gemini MCP server trust: true
	"CFG104": "AVE-2026-00063", // committed Devin permissions.allow: the default is a prompt, and a
	//                             wildcard or a bare privileged binary removes it deterministically,
	//                             with no instruction text. Same shape as CFG093.
	"CFG105": "AVE-2026-00063", // committed OpenCode permission block: both reported cases
	//                             (external_directory, reading .env) are prompts the file removes.

	// Zero-click auto-run on project load (AVE-2026-00064).
	"CFG047": "AVE-2026-00064", // .vscode/tasks.json folderOpen, Zed create_worktree hook task
	"CFG086": "AVE-2026-00064", // committed hook on a zero-click event (workspaceOpen / SessionStart)
	"CFG067": "AVE-2026-00064", // committed project-scoped hooks. Imperfect fit: the record is specific
	//                             to project *load*, CFG067 flags committed hooks on any event.

	// Unpinned dependency, supply-chain substitution (AVE-2026-00062).
	"CFG010": "AVE-2026-00062", // MCP server unpinned @latest/:latest
	"CFG074": "AVE-2026-00062", // skills-lock.json entry with no integrity pin
	"CFG055": "AVE-2026-00062", // Imperfect fit: only the unpinned extraKnownMarketplaces source is
	"CFG089": "AVE-2026-00062", // this class; the enabledPlugins half is supply chain more broadly.
	"CFG098": "AVE-2026-00062", // marketplace.json archive source with no sha256, npm source at a
	//                             non-default registry: nothing pins what the entry installs.

	// TLS verification disabled in component configuration (AVE-2026-00061).
	"CFG075": "AVE-2026-00061", // MCP env/args TLS-verify killswitch

	// Hardcoded credentials (AVE-2026-00047), continued.
	"CFG097": "AVE-2026-00047", // Gemini remote-agent auth literal. Only that half maps: the rule's
	//                             cleartext agent_card_url has no AVE class (00061 is TLS-verify
	//                             disabled, which is a different failure from no TLS at all).

	// Endpoint redirect via a static configuration value (AVE-2026-00073). The
	// record names OTEL_EXPORTER_OTLP_ENDPOINT among its manifestations and is
	// explicit that nothing is injected into the model's context: a committed
	// value changes where the process sends data, so detection is a value
	// comparison rather than content analysis. It shipped for the "telemetry /
	// context redirect via config" class this crosswalk had proposed.
	//
	// CFG071 belongs here too, which the first pass got wrong by reading the
	// record's title rather than its text. The description names three
	// manifestations, and the third is "a model or provider base URL reachable
	// only over cleartext http:// to a remote host, so the API key travels in
	// plaintext", which is CFG071 exactly. Cleartext is not a separate class
	// from redirect here; the record covers both under one mechanism.
	"CFG005": "AVE-2026-00073", // ANTHROPIC_BASE_URL pointing at a non-Anthropic endpoint
	"CFG046": "AVE-2026-00073", // OTEL exporter endpoint redirecting telemetry off-host
	"CFG071": "AVE-2026-00073", // model/provider base URL over cleartext to a remote host
	"CFG099": "AVE-2026-00073", // qwen proxy. Maps on that half only: the rule's sandboxImage half
	//                             has no class, and its unconfirmed auto-skill half is 00063.

	// Container daemon redirected off-host (AVE-2026-00071).
	"CFG082": "AVE-2026-00071", // DOCKER_HOST in an env block, or docker -H in a command site

	// MCP server bound to every interface with no authentication step (AVE-2026-00072).
	"CFG018": "AVE-2026-00072", // bind-all, which the record also calls NeighborJack

	// Natural-language steering of an approval classifier subagent (AVE-2026-00076).
	// The record places itself explicitly between AVE-2026-00021 (instructions to
	// the agent) and AVE-2026-00063 (a setting, no instruction text), which is the
	// gap this crosswalk had recorded for CFG094.
	"CFG094": "AVE-2026-00076", // .cursor/permissions.json autoRun.allow_instructions
	"CFG103": "AVE-2026-00076", // Imperfect fit, and only for one of the rule's three findings:
	//                             features.guardianv2.classifier_instructions replaces the prompt of
	//                             Codex's own reviewer, which is the record's mechanism exactly, a
	//                             committed file aiming natural language at a separate, non-primary
	//                             classifier. cfgaudit reports the stronger form (the whole prompt
	//                             replaced) where the record describes steering. The other two
	//                             findings, enabled = false and a raised review_threshold, have NO
	//                             class: AVE-2026-00063 requires a *human*-approval step, and
	//                             Guardian v2 is an automated reviewer. Reported as a gap.

	// Deliberately unmapped, so the decision is not re-made every release:
	// CFG100 (Grok [plugins] enabled/paths) would need AVE-2026-00064, which
	// requires that Grok's loader runs plugin code at project load with no
	// prompt. That is unverified, and the enabled half is the same wider supply
	// chain shape CFG055/CFG089 already sit outside the map for.
	// CFG101 (a deny rule walked past by flag reordering) is an ineffective
	// guardrail rather than an attacker behaviour. AVE-2026-00063 is a flag that
	// removes a gate and AVE-2026-00068 is composition through shell state;
	// neither is "the denylist misses an equivalent spelling".
	// CFG106 (Codex browser_use / computer_use granted from a committed config)
	// would need AVE-2026-00063, which is a bypassed *human-approval* step. The
	// rule deliberately does not claim that: config/read shows the repository's
	// value reaching the consumer boundary, and the browser and computer use
	// tools live in the app, so whether a prompt is skipped is unverified. A
	// mapping would assert more than the rule's own message does.
	// CFG107 (Codex shell_environment_policy.set injecting code into every
	// spawned shell) has CFG020's mechanism exactly, but AVE-2026-00055 is bound
	// to an untrusted *MCP launch config*, and no record covers a configuration
	// -declared process environment that loads code into every shell the agent
	// runs. Reported as a gap rather than stretched onto 00055.
	// CFG102 (two committed skills claiming one name) is name shadowing, but
	// AVE-2026-00017 is explicitly MCP server identity and AVE-2026-00066 is
	// registry squatting on hallucinated names. Reported as a gap instead.
}

// ruleAVE returns the primary AVE id for a rule, or "" if none is mapped.
func ruleAVE(id string) string { return aveByRule[id] }

var docOwaspLLMRe = regexp.MustCompile(`LLM\d{2}`)

// ruleOWASP returns the OWASP LLM id for a rule, parsed from its doc header —
// the same single source of truth `cfgaudit list` reads. "" if the doc is
// missing or carries no LLM id.
func ruleOWASP(id string) string {
	doc, ok := cfgaudit.RuleDoc(id)
	if !ok {
		return ""
	}
	return docOwaspLLMRe.FindString(doc)
}
