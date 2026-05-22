package rules

import (
	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// Target is the parsed representation of a project's AI-agent configuration.
// Fields are nil/empty when the corresponding file is absent.
type Target struct {
	SettingsFile string
	Settings     *parser.Settings
	Scope        finding.Scope

	IgnoreFile  string
	IgnoreLines []parser.IgnoreLine
}

// userScopeNote returns a message suffix to append to findings that originate
// from a user-global settings.json. The note flags the broader blast radius —
// user-global settings apply to every project the user opens with Claude Code.
// Empty for non-user scopes so callers can unconditionally append.
func userScopeNote(t *Target) string {
	if t == nil || t.Scope != finding.ScopeUser {
		return ""
	}
	return " — user-global scope: this setting applies to every Claude Code project you open"
}

// Rule is implemented by every cfgaudit check.
type Rule interface {
	ID() string
	Check(t *Target) []finding.Finding
}

// All is the ordered list of rules run on every target.
var All []Rule
