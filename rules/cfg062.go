package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg062 struct{}

var CFG062 = &cfg062{}

func init() { All = append(All, CFG062) }

func (r *cfg062) ID() string { return "CFG062" }

// Check flags a Gemini CLI settings.json that explicitly allows installing
// extensions from arbitrary Git repositories (security.blockGitExtensions:
// false) without an allow-list to constrain them — a committed supply-chain
// footgun: any repo the agent is pointed at can ship executable extension code.
// Only fires on an explicit `false` (not the absence of the field) and only when
// security.allowedExtensions does not narrow what may be installed.
func (r *cfg062) Check(t *Target) []finding.Finding {
	if t == nil || t.Gemini == nil {
		return nil
	}
	findings := r.checkExtensionRegistry(t)

	sec := t.Gemini.Security
	if sec == nil {
		return findings
	}
	if sec.BlockGitExtensions == nil || *sec.BlockGitExtensions {
		return findings // absent, or explicitly blocking git extensions — fine
	}
	if len(sec.AllowedExtensions) > 0 {
		return findings // an allow-list constrains what may be installed
	}
	return append(findings, finding.Finding{
		RuleID:   "CFG062",
		Severity: finding.Warn,
		File:     t.GeminiFile,
		Message:  "Gemini security.blockGitExtensions is false with no security.allowedExtensions allow-list — the workspace permits installing extensions from arbitrary Git repositories, a supply-chain vector (extension code runs with the agent's privileges). Set blockGitExtensions: true, or pin an allowedExtensions allow-list" + userScopeNote(t),
	})
}

// checkExtensionRegistry reports a committed experimental.extensionRegistryURI
// that points somewhere other than the default registry. Where extensions are
// discovered from is the same supply chain blockGitExtensions governs, one step
// earlier: it decides the catalogue rather than what may be installed from it.
//
// Read presence-based, per the version-gate convention: the key sits under
// `experimental` and may move or vanish, so nothing here asserts a version.
//
// Verified at the consumer in gemini-cli 0.55.1. The workspace value is honoured
// only inside a trusted folder, which is the same footing as Gemini's MCP trust
// that CFG096 already covers, and an environment variable outranks it:
//
//	let extensionRegistryURI = process.env["GEMINI_CLI_EXTENSION_REGISTRY_URI"]
//	  ?? (trustedFolder ? settings.experimental?.extensionRegistryURI : void 0);
func (r *cfg062) checkExtensionRegistry(t *Target) []finding.Finding {
	if t.Gemini.Experimental == nil {
		return nil
	}
	uri := strings.TrimSpace(t.Gemini.Experimental.ExtensionRegistryURI)
	if uri == "" || strings.EqualFold(uri, parser.DefaultGeminiExtensionRegistry) {
		return nil
	}
	what := "another host"
	if !strings.HasPrefix(strings.ToLower(uri), "http") {
		// Anything that does not start with http is resolved against the working
		// directory, so the repository supplies the catalogue itself.
		what = "a file inside the repository"
	}
	return []finding.Finding{{
		RuleID:   "CFG062",
		Severity: finding.Warn,
		File:     t.GeminiFile,
		Message: "Gemini experimental.extensionRegistryURI is \"" + uri + "\" rather than the default " + parser.DefaultGeminiExtensionRegistry +
			" — every extension the agent discovers comes from " + what + " that this repository chose, one step ahead of whatever allowedExtensions then permits. It applies once the folder is trusted. Remove the key, or confirm the registry is one you run" + userScopeNote(t),
	}}
}
