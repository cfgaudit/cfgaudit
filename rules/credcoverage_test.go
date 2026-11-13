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

// `token` in a deny entry counts as a secret guard only when it is a
// credential file name or path component, not a substring of a source file
// name such as tokens.h or spam-tokens.json (#1662).
func TestGuardsSecrets_TokenFileNames1662(t *testing.T) {
	for _, d := range []string{
		"Edit(syntaqlite-syntax/csrc/tokens.h)",
		"Write(pkg/src/sqlite/tokens.rs)",
		"Edit(pkg/fixtures/safes/spam-tokens.json)",
	} {
		if guardsSecrets([]string{d}) {
			t.Errorf("%q should not count as a secret guard", d)
		}
	}
	for _, d := range []string{
		"Read(./.env)",
		"Read(**/token.json)",
		"Read(~/.config/gh/access_token)",
		"Read(tokens)",
		"Edit(secrets/token/key.pem)",
	} {
		if !guardsSecrets([]string{d}) {
			t.Errorf("%q should count as a secret guard", d)
		}
	}
}

// A deny list that only names a source file with "tokens" in its name guards no
// secret, so a credential-coverage gap is a warning, not an error (#1662).
func TestCredentialCoverage_TokenSourceFile1662(t *testing.T) {
	tg := settingsTarget(t, `{"permissions":{"deny":["Edit(syntaqlite-syntax/csrc/tokens.h)"]}}`)
	for _, r := range []Rule{CFG041, CFG042} {
		f := r.Check(tg)
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("%s: want one warn finding, got %+v", r.ID(), f)
		}
	}
}

// Without a permissions block there is no allow rule that opens a route.
func TestSilentHomeRoute_NoPermissions(t *testing.T) {
	if silentHomeRoute(settingsTarget(t, `{"env":{"A":"1"}}`)) {
		t.Error("no permissions block reported as a silent route")
	}
}

// #1661: a pinned interpreter grant is no route to the home directory, and
// Read(//tmp/**) is not either. Open interpreter grants still are.
func TestSilentHomeRoute_PinnedInterpreters1661(t *testing.T) {
	deny := `"deny":["Read(./.env)","Read(./secrets/**)"]`
	sev := func(allow string) (finding.Severity, finding.Severity) {
		tg := settingsTarget(t, `{"permissions":{"allow":[`+allow+`],`+deny+`}}`)
		var s43, s44 finding.Severity
		for _, f := range CFG043.Check(tg) {
			s43 = f.Severity
		}
		for _, f := range CFG044.Check(tg) {
			s44 = f.Severity
		}
		return s43, s44
	}
	for _, allow := range []string{
		`"Bash(node scripts/check.js:*)","Bash(php -v)"`,
		`"Bash(python3 -m pytest:*)"`,
		`"Bash(python -V:*)"`,
		`"Bash(node --version:*)"`,
		`"Bash(bash scripts/build.sh:*)"`,
		`"Bash(bun -v:*)"`,
		`"Bash(php --version)"`,
		`"Read(//tmp/**)"`,
		`"Read(//etc/hosts)"`,
	} {
		if a, b := sev(allow); a != finding.Warn || b != finding.Warn {
			t.Errorf("%s: CFG043 %q, CFG044 %q, want warn", allow, a, b)
		}
	}
	for _, allow := range []string{
		`"Bash(python:*)"`,
		`"Bash(node -e:*)"`,
		`"Bash(python3.12:*)"`,
		`"Bash(php:*)"`,
		`"Bash(bun:*)"`,
		`"Bash(nodejs *)"`,
		`"Bash(py -c:*)"`,
		`"Bash(python -v:*)"`,
		`"Bash(ruby -v:*)"`,
		`"Bash(bash -c:*)"`,
		`"Bash(python -m pip:*)"`,
		`"Read(//**)"`,
		`"Read(//home/**)"`,
		`"Read(//Users/me/**)"`,
		`"Read(//root/.ssh/id_rsa)"`,
	} {
		if a, b := sev(allow); a != finding.Error || b != finding.Error {
			t.Errorf("%s: CFG043 %q, CFG044 %q, want error", allow, a, b)
		}
	}
	if !interpreterRunsAnyCode("node:*") {
		t.Error("an entry that is not Bash(...) counts as open")
	}
}
