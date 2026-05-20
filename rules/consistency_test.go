package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var ruleIDPattern = regexp.MustCompile(`^CFG\d{3}$`)
var readmeRuleIDRe = regexp.MustCompile(`\bCFG\d{3}\b`)

func TestRuleConsistency(t *testing.T) {
	checkNoDuplicateIDs(t)

	readme := loadFile(t, filepath.Join("..", "README.md"))

	for _, r := range All {
		r := r
		t.Run(r.ID(), func(t *testing.T) {
			id := r.ID()

			if !ruleIDPattern.MatchString(id) {
				t.Errorf("ID %q does not match CFG### format", id)
			}

			checkDocFile(t, id)
			checkREADMEMention(t, id, readme)
		})
	}

	checkNoPhantomREADMEIDs(t, readme)
}

func checkNoDuplicateIDs(t *testing.T) {
	t.Helper()
	seen := map[string]bool{}
	for _, r := range All {
		if seen[r.ID()] {
			t.Errorf("duplicate rule ID %q in All", r.ID())
		}
		seen[r.ID()] = true
	}
}

func checkDocFile(t *testing.T, id string) {
	t.Helper()
	path := filepath.Join("..", "docs", "rules", id+".md")
	content, err := os.ReadFile(path) //nolint:gosec // G304: reads known-safe local test paths
	if err != nil {
		t.Errorf("missing docs/rules/%s.md", id)
		return
	}
	body := string(content)
	if !strings.Contains(body, "OWASP") && !strings.Contains(body, "LLM") {
		t.Errorf("docs/rules/%s.md has no OWASP/LLM reference", id)
	}
}

func checkREADMEMention(t *testing.T, id, readme string) {
	t.Helper()
	if !strings.Contains(readme, id) {
		t.Errorf("%s is not mentioned in README.md", id)
	}
}

// checkNoPhantomREADMEIDs ensures every CFGxxx ID in README.md is backed by a
// registered rule. This catches rules listed in the README before they are implemented.
func checkNoPhantomREADMEIDs(t *testing.T, readme string) {
	t.Helper()
	implemented := map[string]bool{}
	for _, r := range All {
		implemented[r.ID()] = true
	}
	for _, id := range readmeRuleIDRe.FindAllString(readme, -1) {
		if !implemented[id] {
			t.Errorf("README.md mentions %s but no such rule is registered in All", id)
		}
	}
}

func loadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: reads known-safe local test paths
	if err != nil {
		t.Fatalf("could not read %s: %v", path, err)
	}
	return string(data)
}
