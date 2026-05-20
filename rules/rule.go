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

	IgnoreFile  string
	IgnoreLines []parser.IgnoreLine
}

// Rule is implemented by every cfgaudit check.
type Rule interface {
	ID() string
	Check(t *Target) []finding.Finding
}

// All is the ordered list of rules run on every target.
var All []Rule
