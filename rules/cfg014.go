package rules

import (
	"regexp"
	"sort"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg014 struct{}

var CFG014 = &cfg014{}

func init() { All = append(All, CFG014) }

func (r *cfg014) ID() string { return "CFG014" }

// curlPipeInterpreterRe matches `curl ... | bash`-style remote-code execution.
// The character class forbids `\n`, `|`, `;`, `&` between the downloader and
// the pipe so that command-separator chains like `curl x; bash` don't match —
// only true pipelines do. Trailing `\b` prevents matches inside identifiers
// such as "bashed" or "shifter".
var curlPipeInterpreterRe = regexp.MustCompile(`(?:curl|wget)\s+[^\n|;&]*\|\s*(?:bash|sh|zsh|python3?|node|perl)\b`)

func (r *cfg014) Check(t *Target) []finding.Finding {
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
				if h.Command == "" {
					continue
				}
				if !curlPipeInterpreterRe.MatchString(h.Command) {
					continue
				}
				findings = append(findings, finding.Finding{
					RuleID:   "CFG014",
					Severity: finding.Error,
					File:     t.SettingsFile,
					Message:  "hooks." + event + " command pipes curl/wget output directly into a shell or interpreter — this executes unverified remote code every time the hook fires; download to a file first and verify a checksum before running" + userScopeNote(t),
				})
			}
		}
	}
	return findings
}
