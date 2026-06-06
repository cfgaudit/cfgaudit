package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var ruleIDPattern = regexp.MustCompile(`^CFG\d{3}$`)
var readmeRuleIDRe = regexp.MustCompile(`\bCFG\d{3}\b`)
var llmRe = regexp.MustCompile(`LLM\d{2}`)
var sevTokenRe = regexp.MustCompile(`(?i)\b(error|warn|info)\b`)
var findingSevRe = regexp.MustCompile(`finding\.(Error|Warn|Info)\b`)

func TestRuleConsistency(t *testing.T) {
	checkNoDuplicateIDs(t)

	readme := loadFile(t, filepath.Join("..", "README.md"))
	codeSev := codeSeverities(t)

	for _, r := range All {
		r := r
		t.Run(r.ID(), func(t *testing.T) {
			id := r.ID()

			if !ruleIDPattern.MatchString(id) {
				t.Errorf("ID %q does not match CFG### format", id)
			}

			checkDocFile(t, id)
			checkREADMEMention(t, id, readme)
			checkSeverityAndOWASP(t, id, readme, codeSev[id])
		})
	}

	checkNoPhantomREADMEIDs(t, readme)
}

// checkSeverityAndOWASP guards against doc/README drift the existence checks miss:
//   - the doc-header severity must match the README rule-table severity, and
//   - every severity the rule actually emits in code must be documented in one of
//     them (catches e.g. a warn→error scope escalation that the docs omit), and
//   - the OWASP risk in the doc header must match the README rule-table row.
func checkSeverityAndOWASP(t *testing.T, id, readme string, codeSev map[string]bool) {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join("..", "docs", "rules", id+".md")) //nolint:gosec // G304: known-safe local test path
	if err != nil {
		return // checkDocFile already reports a missing doc
	}

	row := readmeRuleRow(readme, id)
	if row == "" {
		t.Errorf("%s: no README rule-table row found", id)
		return
	}
	cells := strings.Split(row, "|")
	var readmeSev map[string]bool
	if len(cells) > 2 {
		readmeSev = sevSet(cells[2])
	}
	docSev := sevSet(severityHeader(string(doc)))

	if !eqSevSet(docSev, readmeSev) {
		t.Errorf("%s: severity mismatch — doc header %v vs README table %v", id, sevList(docSev), sevList(readmeSev))
	}
	documented := func(s string) bool { return docSev[s] || readmeSev[s] }
	for s := range codeSev {
		if !documented(s) {
			t.Errorf("%s: code emits %q severity but neither the doc header nor the README table mentions it", id, s)
		}
	}

	if docLLM, readmeLLM := llmRe.FindString(string(doc)), llmRe.FindString(row); docLLM != readmeLLM {
		t.Errorf("%s: OWASP mismatch — doc %q vs README %q", id, docLLM, readmeLLM)
	}
}

// codeSeverities scans the rule source files for the finding.Error/Warn/Info
// literals each rule emits, keyed by rule ID. A rule that builds its severity
// indirectly may be under-counted, so this is only used to assert that emitted
// severities are documented — never the reverse.
func codeSeverities(t *testing.T) map[string]map[string]bool {
	t.Helper()
	files, err := filepath.Glob("cfg*.go")
	if err != nil {
		t.Fatalf("glob rule sources: %v", err)
	}
	idRe := regexp.MustCompile(`return "(CFG\d{3})"`)
	out := map[string]map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) //nolint:gosec // G304: globbed local test path
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(b)
		m := idRe.FindStringSubmatch(src)
		if m == nil {
			continue
		}
		sev := map[string]bool{}
		for _, s := range findingSevRe.FindAllStringSubmatch(src, -1) {
			sev[strings.ToLower(s[1])] = true
		}
		out[m[1]] = sev
	}
	return out
}

// severityHeader returns the text after "**Severity:**" on the doc's header line.
func severityHeader(doc string) string {
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "**Severity:**") {
			return strings.TrimPrefix(line, "**Severity:**")
		}
	}
	return ""
}

func sevSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, m := range sevTokenRe.FindAllStringSubmatch(s, -1) {
		out[strings.ToLower(m[1])] = true
	}
	return out
}

func eqSevSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sevList(s map[string]bool) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// readmeRuleRow returns the README rule-table row that links to the rule's doc.
func readmeRuleRow(readme, id string) string {
	anchor := "](docs/rules/" + id + ".md)"
	for _, line := range strings.Split(readme, "\n") {
		if strings.Contains(line, anchor) && strings.HasPrefix(strings.TrimSpace(line), "|") {
			return line
		}
	}
	return ""
}

var (
	readmeMCPRowRe = regexp.MustCompile(`(?m)^\|\s*(MCP\d{2})\b(.*)$`)
	cfgIDRe        = regexp.MustCompile(`CFG\d{3}`)
	docMCPHeaderRe = regexp.MustCompile(`\*\*OWASP MCP:\*\*\s*\[(MCP\d{2})`)
)

// TestMCPMappingConsistency keeps the provisional OWASP MCP Top 10 mapping in
// sync between each rule's doc header (**OWASP MCP:** MCPxx) and the README MCP
// mapping table — the same drift guard the LLM mapping gets, so the two never
// diverge as the (still-beta) taxonomy shifts.
func TestMCPMappingConsistency(t *testing.T) {
	readme := loadFile(t, filepath.Join("..", "README.md"))

	readmeMap := map[string]string{}
	for _, m := range readmeMCPRowRe.FindAllStringSubmatch(readme, -1) {
		mcp := m[1]
		for _, id := range cfgIDRe.FindAllString(m[2], -1) {
			if prev, ok := readmeMap[id]; ok && prev != mcp {
				t.Errorf("%s listed under both %s and %s in the README MCP table", id, prev, mcp)
			}
			readmeMap[id] = mcp
		}
	}
	if len(readmeMap) == 0 {
		t.Fatal("no README MCP mapping rows parsed — has the table format changed?")
	}

	docMap := map[string]string{}
	for _, r := range All {
		doc, err := os.ReadFile(filepath.Join("..", "docs", "rules", r.ID()+".md")) //nolint:gosec // G304: known-safe local test path
		if err != nil {
			continue
		}
		if m := docMCPHeaderRe.FindStringSubmatch(string(doc)); m != nil {
			docMap[r.ID()] = m[1]
		}
	}

	for id, mcp := range docMap {
		if readmeMap[id] != mcp {
			t.Errorf("%s: doc header maps to %s but README MCP table says %q", id, mcp, readmeMap[id])
		}
	}
	for id, mcp := range readmeMap {
		if docMap[id] != mcp {
			t.Errorf("%s: README MCP table maps to %s but doc header says %q", id, mcp, docMap[id])
		}
	}
}

// TestAISVSMappingNoPhantomIDs ensures every rule referenced in the provisional
// OWASP AISVS mapping doc is a real, registered rule — so a renamed/removed rule
// can't leave a dangling reference in the mapping.
func TestAISVSMappingNoPhantomIDs(t *testing.T) {
	doc := loadFile(t, filepath.Join("..", "docs", "aisvs-mapping.md"))
	implemented := map[string]bool{}
	for _, r := range All {
		implemented[r.ID()] = true
	}
	seen := false
	for _, id := range cfgIDRe.FindAllString(doc, -1) {
		seen = true
		if !implemented[id] {
			t.Errorf("aisvs-mapping.md references %s but no such rule is registered", id)
		}
	}
	if !seen {
		t.Fatal("no rule IDs found in aisvs-mapping.md — has the file moved?")
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
