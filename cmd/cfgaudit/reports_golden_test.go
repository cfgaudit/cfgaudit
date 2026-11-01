// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/rules"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden report files in testdata/reports")

// goldenFindings covers the shapes a report has to carry: every severity, a
// finding with line and column, one with a line but no column, one without a
// line, a user-scope finding and a path in a subdirectory.
func goldenFindings() []finding.Finding {
	return []finding.Finding{
		{RuleID: "CFG004", Severity: finding.Error, Scope: finding.ScopeProject, File: "/proj/.claude/settings.json", Line: 1, Col: 17, Message: `defaultMode: "bypassPermissions" disables all permission checks`},
		{RuleID: "CFG006", Severity: finding.Warn, Scope: finding.ScopeProject, File: "/proj/.claude/settings.json", Message: "no permissions.deny list"},
		{RuleID: "CFG024", Severity: finding.Error, Scope: finding.ScopeProject, File: "/proj/docs/CLAUDE.md", Line: 3, Message: "hidden Unicode character"},
		{RuleID: "CFG040", Severity: finding.Info, Scope: finding.ScopeUser, File: "/proj/.mcp.json", Line: 2, Col: 5, Message: "user-scope example"},
	}
}

// goldenRules is the rule subset the SARIF golden describes, so adding a rule
// elsewhere does not rewrite the file.
func goldenRules(t *testing.T) []rules.Rule {
	t.Helper()
	want := map[string]bool{"CFG004": true, "CFG006": true, "CFG024": true, "CFG040": true}
	var out []rules.Rule
	for _, r := range rules.All {
		if want[r.ID()] {
			out = append(out, r)
		}
	}
	if len(out) != len(want) {
		t.Fatalf("golden rules: found %d of %d", len(out), len(want))
	}
	return out
}

// TestReportGoldens renders the SARIF, Code Climate and JSON reports for
// goldenFindings and compares them with testdata/reports. The schema
// validation workflow checks the same files against the SARIF 2.1.0 schema and
// GitLab's Code Quality format (#1063), and the JSON one against
// schema/findings.schema.json (#1078), so a report change has to pass both:
// this test makes it visible, the schemas make sure GitHub and GitLab still
// accept it. Run `go test ./cmd/cfgaudit -run TestReportGoldens -update` after
// an intended change.
func TestReportGoldens(t *testing.T) {
	// SARIF carries the file as given; the CLI passes paths relative to where
	// it runs, so the golden uses the same relative form.
	sarifFindings := goldenFindings()
	for i := range sarifFindings {
		rel, err := filepath.Rel("/proj", sarifFindings[i].File)
		if err != nil {
			t.Fatal(err)
		}
		sarifFindings[i].File = filepath.ToSlash(rel)
	}
	cases := []struct {
		file   string
		render func(*bytes.Buffer) error
	}{
		{"sarif.golden.json", func(b *bytes.Buffer) error {
			return encodeSARIF(b, sarifFindings, "1.0.0", goldenRules(t))
		}},
		{"codeclimate.golden.json", func(b *bytes.Buffer) error {
			return encodeCodeClimate(b, goldenFindings(), "/proj")
		}},
		// --format json carries the file as given, like SARIF (#1078).
		{"json.golden.json", func(b *bytes.Buffer) error {
			return encodeJSON(b, sarifFindings)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			var b bytes.Buffer
			if err := tc.render(&b); err != nil {
				t.Fatalf("render: %v", err)
			}
			path := filepath.Join("testdata", "reports", tc.file)
			if *updateGolden {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path) // #nosec G304 -- golden file in this repository
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			// A Windows checkout may turn the golden's line endings into CRLF.
			want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
			if !bytes.Equal(b.Bytes(), want) {
				t.Errorf("%s differs from the rendered report; run with -update if the change is intended\ngot:\n%s", path, b.String())
			}
		})
	}
}
