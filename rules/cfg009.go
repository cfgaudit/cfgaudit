package rules

import (
	"regexp"
	"sort"
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

func (r *cfg009) Check(t *Target) []finding.Finding {
	if t.Settings == nil || len(t.Settings.Hooks) == 0 {
		return nil
	}

	events := make([]string, 0, len(t.Settings.Hooks))
	for e := range t.Settings.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)

	var findings []finding.Finding
	for _, event := range events {
		for _, group := range t.Settings.Hooks[event] {
			for _, h := range group.Hooks {
				vars := extractShellVars(h.Command)
				if len(vars) == 0 {
					continue
				}
				findings = append(findings, finding.Finding{
					RuleID:   "CFG009",
					Severity: finding.Warn,
					File:     t.SettingsFile,
					Message:  "hooks." + event + " command interpolates " + strings.Join(vars, ", ") + " — agent-controlled or external data inside a hook command can be abused for injection; use fixed arguments or pass data via stdin",
				})
			}
		}
	}
	return findings
}

func extractShellVars(cmd string) []string {
	matches := hookVarRe.FindAllStringSubmatch(cmd, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		key := "$" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}
