package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg009 struct{}

var CFG009 = &cfg009{}

func init() { All = append(All, CFG009) }

func (r *cfg009) ID() string { return "CFG009" }

// hookVarRe matches a Bourne-shell variable reference: $NAME or ${NAME}.
// Command substitution ($(...)) and positional/special params ($1, $@, $?) are deliberately not matched.
var hookVarRe = regexp.MustCompile(`\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))`)

// cmdVarRe matches a Windows cmd.exe variable reference: %NAME%.
var cmdVarRe = regexp.MustCompile(`%([A-Za-z_][A-Za-z0-9_]*)%`)

func (r *cfg009) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}

	var findings []finding.Finding
	for _, site := range commandSites(t.Settings) {
		vars := extractShellVars(site.Command)
		if len(vars) == 0 {
			continue
		}
		sev := finding.Warn
		if t.Scope == finding.ScopeUser {
			sev = finding.Error
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG009",
			Severity: sev,
			File:     t.SettingsFile,
			Message:  site.Label + " interpolates " + strings.Join(vars, ", ") + " — agent-controlled or external data inside a command can be abused for injection; use fixed arguments or pass data via stdin" + userScopeNote(t),
		})
	}
	return findings
}

func extractShellVars(cmd string) []string {
	seen := map[string]bool{}
	var out []string
	addKey := func(key string) {
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	for _, m := range hookVarRe.FindAllStringSubmatch(cmd, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		addKey("$" + name)
	}
	for _, m := range cmdVarRe.FindAllStringSubmatch(cmd, -1) {
		addKey("%" + m[1] + "%")
	}
	return out
}
