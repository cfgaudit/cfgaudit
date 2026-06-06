package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg065 struct{}

var CFG065 = &cfg065{}

func init() { All = append(All, CFG065) }

func (r *cfg065) ID() string { return "CFG065" }

// Check flags hardcoded inline API-key literals in a Continue config.yaml —
// `apiKey` on a `models[]` entry (provider credential) or on a remote
// `mcpServers[]` entry. A committed config carrying a real key leaks it to anyone
// with repo access. Continue's own reference syntax (`${{ secrets.NAME }}`, the
// continue-proxy provider's apiKeyLocation) is the safe pattern and is not
// flagged; nor are env-style references or obvious placeholders.
func (r *cfg065) Check(t *Target) []finding.Finding {
	if t == nil || t.Continue == nil {
		return nil
	}
	var findings []finding.Finding
	add := func(where string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG065",
			Severity: finding.Error,
			File:     t.ContinueFile,
			Message:  "Continue " + where + " contains a hardcoded apiKey literal — a committed credential exposed to anyone with repo access. Reference it instead, e.g. apiKey: \"${{ secrets.YOUR_KEY }}\"" + userScopeNote(t),
		})
	}
	for _, m := range t.Continue.Models {
		if isInlineSecretLiteral(m.APIKey) {
			label := "model"
			if name := strings.TrimSpace(m.Name); name != "" {
				label = "model \"" + name + "\""
			}
			add(label + " apiKey")
		}
	}
	for _, s := range t.Continue.MCPServers {
		if isInlineSecretLiteral(s.APIKey) {
			label := "mcpServers"
			if name := strings.TrimSpace(s.Name); name != "" {
				label = "mcpServers \"" + name + "\""
			}
			add(label + " apiKey")
		}
	}
	return findings
}

// inlineSecretPlaceholders are case-insensitive substrings that mark a value as a
// template / example rather than a real credential.
var inlineSecretPlaceholders = []string{"your", "placeholder", "example", "redacted", "changeme", "<", "...", "xxxx", "api_key_here", "enter-"}

// isInlineSecretLiteral reports whether v looks like a real, hardcoded secret
// rather than a reference (${{ … }} / $ENV) or a placeholder.
func isInlineSecretLiteral(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 8 {
		return false
	}
	if strings.HasPrefix(v, "$") || strings.Contains(v, "{{") {
		return false // ${{ secrets.X }} / ${ENV} reference
	}
	low := strings.ToLower(v)
	for _, ph := range inlineSecretPlaceholders {
		if strings.Contains(low, ph) {
			return false
		}
	}
	return true
}
