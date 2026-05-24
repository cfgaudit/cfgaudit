package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg040 struct{}

var CFG040 = &cfg040{}

func init() { All = append(All, CFG040) }

func (r *cfg040) ID() string { return "CFG040" }

var webFetchRe = regexp.MustCompile(`^WebFetch\((.*)\)$`)

// Check flags permissions.allow entries granting unrestricted WebFetch — a bare
// WebFetch or a wildcard domain lets Claude fetch any URL, an exfiltration
// vector. Scoped entries like WebFetch(domain:api.example.com) are not flagged.
func (r *cfg040) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || t.Settings.Permissions == nil {
		return nil
	}
	var findings []finding.Finding
	for _, entry := range t.Settings.Permissions.Allow {
		if !unrestrictedWebFetch(entry) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG040",
			Severity: finding.Warn,
			File:     t.SettingsFile,
			Message: "permissions.allow grants unrestricted WebFetch (\"" + strings.TrimSpace(entry) +
				"\") — Claude can fetch any URL, an exfiltration channel for data or secrets; scope it to specific domains, e.g. WebFetch(domain:api.example.com)" + userScopeNote(t),
		})
	}
	return findings
}

// unrestrictedWebFetch reports whether an allow entry grants WebFetch against
// any URL: a bare WebFetch, an empty body, or a wildcard domain/url.
func unrestrictedWebFetch(entry string) bool {
	e := strings.TrimSpace(entry)
	if e == "WebFetch" {
		return true
	}
	m := webFetchRe.FindStringSubmatch(e)
	if m == nil {
		return false
	}
	body := strings.TrimSpace(m[1])
	return body == "" || body == "*" || body == "domain:*" || body == "url:*"
}
