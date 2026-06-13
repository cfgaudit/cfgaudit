package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg042 struct{}

var CFG042 = &cfg042{}

func init() { All = append(All, CFG042) }

func (r *cfg042) ID() string { return "CFG042" }

// keyCertExtensions are private-key / certificate file extensions that a
// permissions.deny block should cover, with the suggested deny pattern for each.
var keyCertExtensions = []struct{ ext, suggest string }{
	{"pem", "Read(**/*.pem)"},
	{"key", "Read(**/*.key)"},
	{"p12", "Read(**/*.p12)"},
	{"pfx", "Read(**/*.pfx)"},
	{"jks", "Read(**/*.jks)"},
}

// Check flags a permissions.deny block that exists but does not cover common
// private-key / certificate formats. Reports the gaps in one finding. A missing
// deny block entirely is CFG006's job.
func (r *cfg042) Check(t *Target) []finding.Finding {
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
	for _, kc := range keyCertExtensions {
		if !denyCoversAny(deny, regexp.MustCompile(`(?i)\.`+kc.ext+`$`)) {
			missing = append(missing, "*."+kc.ext)
			suggest = append(suggest, kc.suggest)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "CFG042",
		Severity: finding.Error,
		File:     t.SettingsFile,
		Message: "permissions.deny does not restrict private-key / certificate files (" + strings.Join(missing, ", ") +
			") — Claude can read unrotatable cryptographic material; add " + strings.Join(suggest, ", ") + " to permissions.deny" + userScopeNote(t),
	}}
}
