// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// CFG041 to CFG044 grade a gap by what the deny list guards (#1172).
func TestCredentialCoverage_Severity(t *testing.T) {
	type want map[string]finding.Severity
	for _, tc := range []struct {
		name, settings string
		want           want
	}{
		{"deny list for something else", `{"permissions":{"allow":["Bash(npm run test:*)"],"deny":["Bash(git push *)","Edit(./src/generated/**)"]}}`,
			want{"CFG041": finding.Warn, "CFG042": finding.Warn, "CFG043": finding.Warn, "CFG044": finding.Warn}},
		// Claude Code 2.1.316 asks before cat reads a path outside the
		// project even under an allowed Bash(cat:*), so the home-directory
		// classes are a warning there; a bare Read, an interpreter or an
		// additional directory that covers home is a silent route (#1172).
		{"guards .env only, cat allowed", `{"permissions":{"allow":["Bash(cat:*)"],"deny":["Read(./.env)"]}}`,
			want{"CFG042": finding.Error, "CFG043": finding.Warn, "CFG044": finding.Warn}},
		{"guards .env only, Read allowed", `{"permissions":{"allow":["Read"],"deny":["Read(./.env)"]}}`,
			want{"CFG042": finding.Error, "CFG043": finding.Error, "CFG044": finding.Error}},
		{"guards .env only, node allowed", `{"permissions":{"allow":["Bash(node:*)"],"deny":["Read(./.env)"]}}`,
			want{"CFG042": finding.Error, "CFG043": finding.Error, "CFG044": finding.Error}},
		{"guards .env only, home added", `{"permissions":{"additionalDirectories":["~"],"deny":["Read(./.env)"]}}`,
			want{"CFG042": finding.Error, "CFG043": finding.Error, "CFG044": finding.Error}},
		{"guards .env only, Read of home allowed", `{"permissions":{"allow":["Read(~/**)"],"deny":["Read(./.env)"]}}`,
			want{"CFG042": finding.Error, "CFG043": finding.Error, "CFG044": finding.Error}},
		{"bypass mode, no secret rules", `{"permissions":{"defaultMode":"bypassPermissions","deny":["Bash(git push *)"]}}`,
			want{"CFG041": finding.Error, "CFG042": finding.Error, "CFG043": finding.Error, "CFG044": finding.Error}},
		{"pem and key denied", `{"permissions":{"deny":["Read(**/.env)","Read(//**/.ssh/**)","Read(**/*.pem)","Read(**/*.key)","Read(//**/.aws/**)","Read(//**/.config/gcloud/**)","Read(//**/application_default_credentials.json)","Read(//**/.azure/**)"]}}`,
			want{"CFG042": finding.Warn}},
		{"aws only", `{"permissions":{"deny":["Read(**/.env)","Read(//**/.ssh/**)","Read(**/*.pem)","Read(**/*.key)","Read(**/*.p12)","Read(**/*.pfx)","Read(**/*.jks)","Read(//**/.aws/**)"]}}`,
			want{"CFG043": finding.Warn}},
	} {
		tg := settingsTarget(t, tc.settings)
		got := want{}
		for _, r := range []Rule{CFG041, CFG042, CFG043, CFG044} {
			for _, f := range r.Check(tg) {
				got[f.RuleID] = f.Severity
			}
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
			continue
		}
		for id, sev := range tc.want {
			if got[id] != sev {
				t.Errorf("%s: %s = %q, want %q", tc.name, id, got[id], sev)
			}
		}
	}
}

// Without a permissions block there is no allow rule that opens a route.
func TestSilentHomeRoute_NoPermissions(t *testing.T) {
	if silentHomeRoute(settingsTarget(t, `{"env":{"A":"1"}}`)) {
		t.Error("no permissions block reported as a silent route")
	}
}
