package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var ruleIDPattern = regexp.MustCompile(`^CFG\d{3}$`)

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

func loadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: reads known-safe local test paths
	if err != nil {
		t.Fatalf("could not read %s: %v", path, err)
	}
	return string(data)
}
