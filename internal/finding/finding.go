package finding

import "fmt"

type Severity string

const (
	Error Severity = "error"
	Warn  Severity = "warn"
	Info  Severity = "info"
)

func (s Severity) String() string { return string(s) }

type Finding struct {
	RuleID   string
	Severity Severity
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
