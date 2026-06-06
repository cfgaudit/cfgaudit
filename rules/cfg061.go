package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg061 struct{}

var CFG061 = &cfg061{}

func init() { All = append(All, CFG061) }

func (r *cfg061) ID() string { return "CFG061" }

// Check flags a Gemini CLI settings.json that weakens the tool sandbox — the
// Gemini analog of CFG022. A sandboxAllowedPaths entry that opens the filesystem
// root or the home directory removes path isolation (error); sandboxNetworkAccess
// gives the sandboxed tools unrestricted network egress (warn).
func (r *cfg061) Check(t *Target) []finding.Finding {
	if t == nil || t.Gemini == nil || t.Gemini.Tools == nil {
		return nil
	}
	tools := t.Gemini.Tools
	var findings []finding.Finding

	for _, p := range tools.SandboxAllowedPaths {
		if isBroadSandboxPath(p) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG061",
				Severity: finding.Error,
				File:     t.GeminiFile,
				Message: "Gemini tools.sandboxAllowedPaths includes the broad path \"" + p +
					"\" — exposing the filesystem root or home directory to sandboxed tools defeats path isolation (analogous to weakening Claude Code's sandbox, CFG022). Scope it to the specific directories the tools need" + userScopeNote(t),
			})
		}
	}

	if tools.SandboxNetworkAccess {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG061",
			Severity: finding.Warn,
			File:     t.GeminiFile,
			Message:  "Gemini tools.sandboxNetworkAccess is true — sandboxed tools get unrestricted network egress, an exfiltration / SSRF channel. Disable it unless a tool genuinely needs the network" + userScopeNote(t),
		})
	}
	return findings
}

// isBroadSandboxPath reports whether a sandbox allow-path entry effectively
// removes filesystem isolation (root, home, or a parent-traversal anchor).
func isBroadSandboxPath(p string) bool {
	p = strings.TrimSpace(p)
	switch p {
	case "/", "~", "$HOME", "${HOME}", "..", "/*", "~/*":
		return true
	}
	return strings.HasPrefix(p, "~/..") || strings.HasPrefix(p, "../")
}
