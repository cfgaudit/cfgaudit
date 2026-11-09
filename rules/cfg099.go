// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

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
// with. CFG091 covers the approval mode; this rule covers the keys that decide
// where the traffic goes, what container the sandbox is, whether generated
// skills reach the library unreviewed, and where skills load from.
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
	if t == nil {
		return nil
	}
	if len(t.QwenWebSearchLeaks) > 0 {
		return qwenWebSearchFindings(t)
	}
	if t.Qwen == nil {
		return nil
	}
	modelFindings := qwenModelProviderFindings(t)
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

	// skills.directories outside the repository (#973). Qwen loads them as
	// personal skills, so their allowedTools and hooks are not gated by folder
	// trust, and no review of this repository covers what is there.
	for _, d := range t.QwenSkillDirsOutside {
		add(finding.Warn, "qwen skills.directories names \""+d+"\", outside the repository: Qwen loads every <name>/SKILL.md there as a personal skill, whose allowedTools and hooks folder trust does not gate, and no review of this repository covers that folder on the reader's machine. cfgaudit does not read it."+
			" Keep shared skills in the repository, in .qwen/skills or a folder listed by a relative path")
	}
	return append(findings, modelFindings...)
}

// qwenWebSearchFindings reports a web search backend whose host only the
// repository admits (#974). qwen sends the API key as a bearer token with each
// search, and the schema of tools.webSearch.allowedHosts says so: "The
// configured host receives the API key". It is an error when the repository
// also picks the search model, so the backend is used as soon as the agent
// searches, and a warning when the reader's own settings must pick one.
func qwenWebSearchFindings(t *Target) []finding.Finding {
	var out []finding.Finding
	for _, l := range t.QwenWebSearchLeaks {
		sev, when := finding.Error, "with every web search"
		if !l.Selected {
			sev, when = finding.Warn, "with every web search once a search model is set, which this repository leaves to the reader's settings"
		}
		out = append(out, finding.Finding{
			RuleID: "CFG099", Severity: sev, Scope: t.Scope, File: l.File,
			Message: "qwen web search backend " + l.Key + " is \"" + l.URL + "\", and " + l.AllowedBy + " admits its host " + l.Host +
				": qwen sends the reader's " + l.KeyEnv + " to that host " + when + ". The host is the repository's choice, not DashScope's. Remove the entries, or set them in your user settings",
		})
	}
	return out
}

// qwenNonModelKeys are credentials of something other than a model API. A
// committed modelProviders entry that names one as envKey sends it to the
// entry's baseUrl as the model API key (#1565).
var qwenNonModelKeys = map[string]bool{
	"GITHUB_TOKEN": true, "GH_TOKEN": true, "GITLAB_TOKEN": true, "NPM_TOKEN": true, "NODE_AUTH_TOKEN": true,
	"AWS_SECRET_ACCESS_KEY": true, "AWS_ACCESS_KEY_ID": true, "AWS_SESSION_TOKEN": true, "AZURE_CLIENT_SECRET": true,
	"DOCKER_PASSWORD": true, "PYPI_TOKEN": true, "CARGO_REGISTRY_TOKEN": true, "SLACK_TOKEN": true, "STRIPE_SECRET_KEY": true,
}

// qwenVendorKeys are model API keys named for one vendor, with that vendor's
// host suffixes. OPENAI_API_KEY is not here: Qwen's OpenAI-compatible
// provider reads it for any endpoint, and committed configs pair it with
// DashScope as often as with OpenAI.
var qwenVendorKeys = map[string][]string{
	"DASHSCOPE_API_KEY": {"aliyuncs.com", "qwencloudapi.com", "qianwenaiapi.com"}, "BAILIAN_CODING_PLAN_API_KEY": {"aliyuncs.com"},
	"BAILIAN_TOKEN_PLAN_API_KEY": {"aliyuncs.com"}, "GEMINI_API_KEY": {"googleapis.com"}, "GOOGLE_API_KEY": {"googleapis.com"},
	"ANTHROPIC_API_KEY": {"anthropic.com"}, "OPENROUTER_API_KEY": {"openrouter.ai"}, "DEEPSEEK_API_KEY": {"deepseek.com"},
	"MOONSHOT_API_KEY": {"moonshot.cn", "moonshot.ai"}, "XAI_API_KEY": {"x.ai"}, "MISTRAL_API_KEY": {"mistral.ai"}, "GROQ_API_KEY": {"groq.com"},
}

// qwenModelProviderFindings reports a committed modelProviders entry whose
// envKey sends a credential to a host it does not belong to (#1565):
// modelProviders, model.name and security.auth.selectedType are on none of
// qwen's workspace restriction lists, so the repository picks both the
// endpoint and which of the reader's variables goes there. An error when the
// file also selects the entry, a warning when the reader would pick it.
func qwenModelProviderFindings(t *Target) []finding.Finding {
	if t.Scope == finding.ScopeUser {
		return nil
	}
	var out []finding.Finding
	for _, p := range t.Qwen.ModelProviderEntries() {
		host := p.Host()
		if p.EnvKey == "" || host == "" || proxyTargetsLoopback(p.BaseURL) {
			continue
		}
		reason := ""
		if qwenNonModelKeys[p.EnvKey] {
			reason = p.EnvKey + " is not a model API key at all"
		} else if suffixes, ok := qwenVendorKeys[p.EnvKey]; ok && !hostUnderAny(host, suffixes) {
			reason = p.EnvKey + " belongs to " + strings.Join(suffixes, " / ") + ", not to this host"
		}
		if reason == "" {
			continue
		}
		sev, when := finding.Warn, "once the reader picks this model"
		if p.Selected {
			sev, when = finding.Error, "in every session, since model.name in this file selects it"
		}
		out = append(out, finding.Finding{RuleID: "CFG099", Severity: sev, Scope: t.Scope, File: t.QwenFile,
			Message: "qwen modelProviders." + p.AuthType + "[" + p.ID + "] sends the reader's " + p.EnvKey + " to " + host + " " + when + ": " + reason +
				". modelProviders is not restricted from the workspace, so the repository picks both the endpoint and the variable. Use a key named for this endpoint, or keep the provider in your user settings"})
	}
	return out
}

func hostUnderAny(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}
