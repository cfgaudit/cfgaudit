package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg043 struct{}

var CFG043 = &cfg043{}

func init() { All = append(All, CFG043) }

func (r *cfg043) ID() string { return "CFG043" }

// cloudProviders maps each cloud provider to a deny pattern that covers its
// credential files and the suggested entries to add.
var cloudProviders = []struct {
	name    string
	re      *regexp.Regexp
	suggest []string
}{
	{"AWS", regexp.MustCompile(`(?i)\.aws(/|\*|$)`),
		[]string{"Read(**/.aws/credentials)", "Read(**/.aws/config)"}},
	{"GCP", regexp.MustCompile(`(?i)gcloud|application_default_credentials`),
		[]string{"Read(**/.config/gcloud/**)", "Read(**/application_default_credentials.json)"}},
	{"Azure", regexp.MustCompile(`(?i)\.azure(/|\*|$)`),
		[]string{"Read(**/.azure/**)"}},
}

// Check flags a permissions.deny block that exists but does not cover cloud
// provider credential files (AWS, GCP, Azure) — Claude could read and exfiltrate
// infrastructure access keys. A missing deny block entirely is CFG006's job.
func (r *cfg043) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	deny := t.Settings.Permissions.Deny
	if len(deny) == 0 {
		return nil
	}
	if denyCoversEverything(deny, t.ClaudeVersion) {
		return nil // a deny-all "*"/Read(**) entry already blocks every read
	}
	var missing, suggest []string
	for _, p := range cloudProviders {
		if !denyCoversAny(deny, p.re) {
			missing = append(missing, p.name)
			suggest = append(suggest, p.suggest...)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG043",
		Severity: finding.Error,
		File:     t.SettingsFile,
		Message: "permissions.deny does not restrict cloud credential files for " + strings.Join(missing, ", ") +
			" — Claude can read and exfiltrate infrastructure access keys; add " + strings.Join(suggest, ", ") + " to permissions.deny" + userScopeNote(t),
	}}
}
