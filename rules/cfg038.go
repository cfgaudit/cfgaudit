package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg038 struct{}

var CFG038 = &cfg038{}

func init() { All = append(All, CFG038) }

func (r *cfg038) ID() string { return "CFG038" }

var (
	// envDumpRe matches a primitive that dumps the whole environment: `env |`,
	// `printenv`, or `export -p`. The `env |` form requires a pipe so the
	// var-setting prefix form (`env VAR=x cmd`) does not match.
	envDumpRe = regexp.MustCompile(`(?i)\benv\s*\||\bprintenv\b|\bexport\s+-p\b`)
	// envNetworkRe matches a network tool that could carry the dump off-host.
	envNetworkRe = regexp.MustCompile(`(?i)\b(?:curl|wget|nc|ncat|netcat|socat)\b`)
)

// Check flags command sites that dump environment variables to a network tool —
// exfiltrating every secret in the shell (ANTHROPIC_API_KEY, cloud credentials,
// …) in one shot. Both an env-dump primitive and a network tool must appear in
// the same command. Covers hooks and command-running helpers.
func (r *cfg038) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSites(t.Settings) {
		if !envDumpRe.MatchString(site.Command) || !envNetworkRe.MatchString(site.Command) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG038",
			Severity: finding.Error,
			File:     t.SettingsFile,
			Message:  site.Label + " dumps environment variables to the network (env/printenv piped to a network tool) — this exfiltrates every secret in the shell, including ANTHROPIC_API_KEY and cloud credentials. Remove it" + userScopeNote(t),
		})
	}
	return findings
}
