package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg099 struct{}

var CFG099 = &cfg099{}

func init() { All = append(All, CFG099) }

func (r *cfg099) ID() string { return "CFG099" }

// Check flags a committed qwen-code .qwen/settings.json that picks the
// infrastructure the agent runs through, rather than the permissions it runs
// with. CFG091 covers the approval mode; this rule covers the three keys that
// decide where the traffic goes, what container the sandbox is, and whether
// generated skills reach the library unreviewed.
//
// Severity backdrop, shared with CFG091: qwen ships folder trust DISABLED by
// default (security.folderTrust.enabled ?? false), so a committed
// .qwen/settings.json applies with no trust prompt. There is no gate here of the
// kind Codex and Cursor put in front of a project layer.
//
// tools.autoAccept is deliberately absent. It is vestigial in qwen: in the
// shipped 0.21.11 bundle the string occurs four times and every one of them is a
// declaration (the v1→v2 migration map, the migration indicator list, the schema
// itself), with nothing reading the value. Reporting it would name an effect that
// does not exist. See the note in internal/parser/qwen.go.
func (r *cfg099) Check(t *Target) []finding.Finding {
	if t == nil || t.Qwen == nil {
		return nil
	}
	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG099",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.QwenFile,
			Message:  msg + userScopeNote(t),
		})
	}

	// proxy routes the CLI's own HTTP requests, which carry the model credential.
	// Loopback is skipped for the same reason CFG021 skips it: pointing at a local
	// interceptor is a debugging setup, not remote redirection.
	if proxy := strings.TrimSpace(t.Qwen.Proxy); proxy != "" && !proxyTargetsLoopback(proxy) {
		add(finding.Error, "qwen proxy is \""+proxy+"\" — every HTTP request the CLI makes goes through a host this repository chose, and it takes precedence over the proxy environment variables."+
			" Measured against qwen 0.21.11, a committed workspace value made the CLI issue \"CONNECT api.openai.com:443\" to it, so this carries the model traffic and the credential header on it: MITM and header capture, the threat model CFG021 covers for a single MCP server, here for the whole CLI. Remove it, or set it from your user settings")
	}

	image := ""
	if t.Qwen.Tools != nil {
		image = strings.TrimSpace(t.Qwen.Tools.SandboxImage)
	}
	if image != "" {
		if t.Qwen.SandboxEnabledInSettings() {
			add(finding.Error, "qwen tools.sandboxImage is \""+image+"\" and tools.sandbox is on in the same file — the agent runs inside a container this repository picked, chosen and enabled together."+
				" Anything the image's entrypoint does happens around every tool call. Pin the image somewhere the reader controls, or drop the key and let the shipped default apply")
		} else {
			add(finding.Warn, "qwen tools.sandboxImage is \""+image+"\" — it names the container the agent's sandbox runs from, ahead of the shipped default."+
				" No sandbox is switched on in this file, so it is latent: it decides the container the moment anyone runs with --sandbox or QWEN_SANDBOX. Pin the image somewhere the reader controls, or drop the key")
		}
	}

	// The auto-skill pair. Only the combination is a finding: the confirmation is
	// meaningless while the feature that produces the skills is off, and
	// enableAutoSkill on its own keeps its confirmation prompt.
	if t.Qwen.AutoSkillsSavedUnconfirmed() {
		add(finding.Error, "qwen memory.enableAutoSkill is true and memory.autoSkillConfirm is false — auto-generated skills are written straight into the skill library with no confirmation."+
			" Note the inverted default: autoSkillConfirm ships as true, so false is the weakening value here, unlike the disable* keys. A skill in the library is instruction content the agent later follows, so this turns a session into a way to plant one. Leave autoSkillConfirm unset")
	}
	return findings
}
