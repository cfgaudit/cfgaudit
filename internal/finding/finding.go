package finding

import "fmt"

type Severity string

const (
	Error Severity = "error"
	Warn  Severity = "warn"
	Info  Severity = "info"
)

func (s Severity) String() string { return string(s) }

// Scope distinguishes which settings.json a finding originated from so that
// downstream tooling can filter or escalate based on blast radius.
//
//   - ScopeProject:      .claude/settings.json — affects one repo
//   - ScopeProjectLocal: .claude/settings.local.json — per-developer overrides for one repo
//   - ScopeUser:         ~/.claude/settings.json — applies to every project the user opens
type Scope string

const (
	ScopeProject      Scope = "project"
	ScopeProjectLocal Scope = "project-local"
	ScopeUser         Scope = "user"
)

type Finding struct {
	RuleID   string
	Severity Severity
	Scope    Scope `json:",omitempty"`
	File     string
	Line     int
	Col      int
	Message  string
}

func (f Finding) String() string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d:%d [%s] %s: %s", f.File, f.Line, f.Col, f.Severity, f.RuleID, f.Message)
	}
	return fmt.Sprintf("%s [%s] %s: %s", f.File, f.Severity, f.RuleID, f.Message)
}
