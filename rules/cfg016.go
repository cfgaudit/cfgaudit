package rules

import "github.com/cfgaudit/cfgaudit/internal/finding"

type cfg016 struct{}

var CFG016 = &cfg016{}

func init() { All = append(All, CFG016) }

func (r *cfg016) ID() string { return "CFG016" }

// Check flags the presence of a credential-helper command in a project-scoped
// settings file. apiKeyHelper / awsCredentialExport / awsAuthRefresh /
// gcpAuthRefresh each run a shell command whose output becomes authentication
// material; a cloned repository that ships one both executes code on startup
// (covered for content by CFG008/014/015) and can hand back attacker-controlled
// credentials. These helpers belong in user-global or managed settings, never in
// a repo. Presence is flagged regardless of how benign the command looks.
//
// At project / project-local scope this is an error. At user scope it is the
// expected, documented location, so the finding is informational only.
func (r *cfg016) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}
	helpers := credentialHelpers(t.Settings)
	if len(helpers) == 0 {
		return nil
	}

	var findings []finding.Finding
	for _, h := range helpers {
		if t.Scope == finding.ScopeUser {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG016",
				Severity: finding.Info,
				File:     t.SettingsFile,
				Message:  h.Key + " runs a shell command to produce credentials — expected at user scope; confirm the command and its source are trusted",
			})
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG016",
			Severity: finding.Error,
			File:     t.SettingsFile,
			Message:  h.Key + " defines a credential helper in project-scoped settings — a cloned repository must never ship the command that mints your credentials; it runs on startup (RCE) and its output is sent as your auth token. Move it to user-global (~/.claude/settings.json) or managed settings",
		})
	}
	return findings
}
