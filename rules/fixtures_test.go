package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/parser"
)

var fixtureIDPattern = regexp.MustCompile(`^(CFG\d{3})_`)

// TestValidFixtures_NoFindings loads every testdata/settings/valid/*.json and asserts
// that no rule produces any finding. A failure here means a fixture has drifted out
// of sync with a rule or a new rule fires on legitimate config.
func TestValidFixtures_NoFindings(t *testing.T) {
	matches := globFixtures(t, filepath.Join("..", "testdata", "settings", "valid", "*.json"))
	for _, path := range matches {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			target := loadFixtureTarget(t, path)
			var got []string
			for _, r := range All {
				for _, f := range r.Check(target) {
					got = append(got, f.String())
				}
			}
			if len(got) > 0 {
				t.Errorf("expected zero findings, got %d:\n%s", len(got), strings.Join(got, "\n"))
			}
		})
	}
}

// TestInvalidFixtures_TriggerNamedRule loads every testdata/settings/invalid/CFG###_*.json
// and asserts that the rule named in the filename produces at least one finding.
// This keeps fixtures and rule implementations in lockstep.
func TestInvalidFixtures_TriggerNamedRule(t *testing.T) {
	matches := globFixtures(t, filepath.Join("..", "testdata", "settings", "invalid", "*.json"))
	for _, path := range matches {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			name := filepath.Base(path)
			m := fixtureIDPattern.FindStringSubmatch(name)
			if m == nil {
				t.Fatalf("fixture %q must be named CFG###_<slug>.json", name)
			}
			expected := m[1]

			target := loadFixtureTarget(t, path)
			var rule Rule
			for _, r := range All {
				if r.ID() == expected {
					rule = r
					break
				}
			}
			if rule == nil {
				t.Fatalf("fixture references unknown rule %q", expected)
			}
			if findings := rule.Check(target); len(findings) == 0 {
				t.Errorf("fixture %s did not trigger %s", name, expected)
			}
		})
	}
}

func globFixtures(t *testing.T, pattern string) []string {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %q: %v", pattern, err)
	}
	if len(matches) == 0 {
		t.Fatalf("no fixtures matched %q", pattern)
	}
	return matches
}

func loadFixtureTarget(t *testing.T, path string) *Target {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: reads known-safe local test paths
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s, err := parser.ParseSettingsBytes(data, path)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return &Target{SettingsFile: path, Settings: s}
}
