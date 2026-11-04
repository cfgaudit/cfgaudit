// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/cfgaudit/cfgaudit/rules"
)

// The advisory list (#1423): docs/advisories.yml says which known attacks
// cfgaudit sees and at which severity, and the website prints it. These tests
// keep every line of it true: the structure, the fixtures and both directions
// of the links to the rule docs.

type advisoryRule struct {
	Rule     string `yaml:"rule"`
	Severity string `yaml:"severity"`
}

type advisoryStep struct {
	Step   string   `yaml:"step"`
	Rules  []string `yaml:"rules"`
	Reason string   `yaml:"reason"`
}

type advisory struct {
	ID       string         `yaml:"id"`
	Aliases  []string       `yaml:"aliases"`
	Kind     string         `yaml:"kind"`
	Agent    string         `yaml:"agent"`
	Fixed    string         `yaml:"fixed"`
	Summary  string         `yaml:"summary"`
	Coverage string         `yaml:"coverage"`
	Rules    []advisoryRule `yaml:"rules"`
	Related  []string       `yaml:"related"`
	Reason   string         `yaml:"reason"`
	Issue    int            `yaml:"issue"`
	Note     string         `yaml:"note"`
	Steps    []advisoryStep `yaml:"steps"`
}

// advisoryIDRe matches the ids a rule doc can cite.
var advisoryIDRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}`)

const (
	advisoriesFile = "../../docs/advisories.yml"
	advisoryDocs   = "../../docs/rules"
	advisoryTxtars = "../../testdata/advisories"
	advisorySummax = 140

	// advisoryClaudeVersion pins the severities: some rules depend on the
	// detected Claude Code, and CI has none.
	advisoryClaudeVersion = "2.1.317"
)

func loadAdvisories(t *testing.T) []advisory {
	t.Helper()
	f, err := os.Open(advisoriesFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var list []advisory
	if err := dec.Decode(&list); err != nil {
		t.Fatalf("%s: %v", advisoriesFile, err)
	}
	if len(list) == 0 {
		t.Fatal("no advisories")
	}
	return list
}

// checkAdvisory returns what is wrong with one entry.
func checkAdvisory(a advisory, known map[string]bool) []string {
	var bad []string
	report := func(s string) { bad = append(bad, s) }
	if a.ID == "" || a.Agent == "" || a.Summary == "" {
		report("id, agent and summary are required")
	}
	switch a.Kind {
	case "cve":
		if !advisoryIDRe.MatchString(a.ID) || advisoryIDRe.FindString(a.ID) != a.ID {
			report("a cve entry needs a CVE or GHSA id")
		}
		if len(a.Steps) > 0 {
			report("steps belong to a campaign")
		}
	case "campaign":
		if advisoryIDRe.MatchString(a.ID) {
			report("a campaign is named, not numbered")
		}
		if len(a.Steps) == 0 {
			report("a campaign needs steps")
		}
	default:
		report("kind must be cve or campaign")
	}
	for _, alias := range a.Aliases {
		if advisoryIDRe.FindString(alias) != alias {
			report("alias " + alias + " is not a CVE or GHSA id")
		}
	}
	if n := len([]rune(a.Summary)); n > advisorySummax {
		report("summary is too long for the website")
	}
	if strings.Contains(a.Summary+a.Note, "—") {
		report("no em dashes")
	}
	if !strings.HasSuffix(a.Summary, ".") {
		report("summary must be a sentence")
	}
	switch a.Coverage {
	case "full":
		if len(a.Rules) == 0 {
			report("coverage full needs rules")
		}
		if a.Reason != "" {
			report("coverage full takes no reason")
		}
	case "partial":
		if len(a.Rules) == 0 || a.Reason == "" {
			report("coverage partial needs rules and a reason")
		}
	case "none":
		if len(a.Rules) != 0 {
			report("coverage none takes no rules, use related")
		}
		if a.Reason == "" {
			report("coverage none needs a reason")
		}
	default:
		report("coverage must be full, partial or none")
	}
	bad = append(bad, checkAdvisoryReason(a.Reason, a.Issue, a.Note)...)
	for _, r := range a.Rules {
		if !known[r.Rule] {
			report("unknown rule " + r.Rule)
		}
		if !slices.Contains([]string{"error", "warn", "info"}, r.Severity) {
			report("severity of " + r.Rule + " must be error, warn or info")
		}
	}
	listed := advisoryRuleIDs(a)
	for _, r := range a.Related {
		if !known[r] {
			report("unknown rule " + r)
		}
	}
	for _, s := range a.Steps {
		if s.Step == "" || len(s.Rules) == 0 && s.Reason == "" {
			report("a step needs a text and rules or a reason")
		}
		for _, r := range s.Rules {
			if !listed[r] {
				report("step rule " + r + " is not in rules")
			}
		}
	}
	return bad
}

func checkAdvisoryReason(reason string, issue int, note string) []string {
	switch reason {
	case "":
		if issue != 0 || note != "" {
			return []string{"issue and note need a reason"}
		}
	case "no-rule-yet":
		if issue == 0 {
			return []string{"no-rule-yet needs an issue"}
		}
	case "not-static", "by-design":
		if note == "" {
			return []string{reason + " needs a note"}
		}
	default:
		return []string{"reason must be not-static, no-rule-yet or by-design"}
	}
	return nil
}

// advisoryRuleIDs is the set of rules an entry claims to fire or cite.
func advisoryRuleIDs(a advisory) map[string]bool {
	out := map[string]bool{}
	for _, r := range a.Rules {
		out[r.Rule] = true
	}
	for _, r := range a.Related {
		out[r] = true
	}
	return out
}

func TestAdvisories_Structure(t *testing.T) {
	known := map[string]bool{}
	for _, r := range rules.All {
		known[r.ID()] = true
	}
	list := loadAdvisories(t)
	seen := map[string]bool{}
	for i, a := range list {
		for _, bad := range checkAdvisory(a, known) {
			t.Errorf("%s: %s", a.ID, bad)
		}
		for _, id := range append([]string{a.ID}, a.Aliases...) {
			if seen[id] {
				t.Errorf("%s: id %s appears twice", a.ID, id)
			}
			seen[id] = true
		}
		if i > 0 && !advisoryBefore(list[i-1], a) {
			t.Errorf("%s: out of order, entries are sorted by id with campaigns last", a.ID)
		}
	}
}

func advisoryBefore(a, b advisory) bool {
	if a.Kind != b.Kind {
		return a.Kind == "cve"
	}
	return a.ID < b.ID
}

// TestAdvisories_StructureCheck feeds checkAdvisory broken entries, so the
// structure test above cannot pass by accepting everything.
func TestAdvisories_StructureCheck(t *testing.T) {
	known := map[string]bool{"CFG001": true}
	good := advisory{
		ID: "CVE-2026-1234", Kind: "cve", Agent: "x", Summary: "A sentence.", Coverage: "full",
		Rules: []advisoryRule{{"CFG001", "error"}},
	}
	if bad := checkAdvisory(good, known); len(bad) != 0 {
		t.Fatalf("good entry rejected: %v", bad)
	}
	tests := map[string]func(a *advisory){
		"no agent":       func(a *advisory) { a.Agent = "" },
		"no summary":     func(a *advisory) { a.Summary = "" },
		"long summary":   func(a *advisory) { a.Summary = strings.Repeat("x", advisorySummax) + "." },
		"em dash":        func(a *advisory) { a.Summary = "A — sentence." },
		"kind":           func(a *advisory) { a.Kind = "bug" },
		"bad id":         func(a *advisory) { a.ID = "CVE-1" },
		"bad alias":      func(a *advisory) { a.Aliases = []string{"nope"} },
		"coverage":       func(a *advisory) { a.Coverage = "most" },
		"full no rules":  func(a *advisory) { a.Rules = nil },
		"full reason":    func(a *advisory) { a.Reason = "not-static"; a.Note = "n." },
		"partial no why": func(a *advisory) { a.Coverage = "partial" },
		"none rules":     func(a *advisory) { a.Coverage = "none"; a.Reason = "not-static"; a.Note = "n." },
		"none no why":    func(a *advisory) { a.Coverage = "none"; a.Rules = nil },
		"unknown rule":   func(a *advisory) { a.Rules[0].Rule = "CFG999" },
		"severity":       func(a *advisory) { a.Rules[0].Severity = "high" },
		"related":        func(a *advisory) { a.Related = []string{"CFG999"} },
		"steps on a cve": func(a *advisory) { a.Steps = []advisoryStep{{Step: "s", Reason: "not-static"}} },
		"no issue": func(a *advisory) {
			a.Coverage, a.Rules, a.Reason = "none", nil, "no-rule-yet"
		},
		"no note": func(a *advisory) {
			a.Coverage, a.Rules, a.Reason = "none", nil, "by-design"
		},
		"bad reason": func(a *advisory) {
			a.Coverage, a.Rules, a.Reason = "none", nil, "later"
		},
		"stray note": func(a *advisory) { a.Note = "n." },
		"campaign without steps": func(a *advisory) {
			a.ID, a.Kind = "Name", "campaign"
		},
		"campaign with a number": func(a *advisory) {
			a.Kind, a.Steps = "campaign", []advisoryStep{{Step: "s", Rules: []string{"CFG001"}}}
		},
		"empty step": func(a *advisory) {
			a.ID, a.Kind, a.Steps = "Name", "campaign", []advisoryStep{{Step: "s"}}
		},
		"step rule": func(a *advisory) {
			a.ID, a.Kind, a.Steps = "Name", "campaign", []advisoryStep{{Step: "s", Rules: []string{"CFG999"}}}
		},
	}
	for name, breakIt := range tests {
		a := good
		a.Rules = slices.Clone(good.Rules)
		breakIt(&a)
		if bad := checkAdvisory(a, known); len(bad) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

func advisorySlug(id string) string {
	return strings.ToLower(strings.ReplaceAll(id, " ", "-"))
}

// parseTxtar splits a fixture into its files. The format is the one of
// golang.org/x/tools/txtar: a comment, then "-- path --" lines before each file.
// Fixtures are archives so that no .claude/, .mcp.json or bare repository sits
// in this repository's tree where an agent or a scanner would pick it up.
func parseTxtar(s string) map[string]string {
	files := map[string]string{}
	name := ""
	for line := range strings.SplitAfterSeq(s, "\n") {
		p, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "-- ")
		if ok && strings.HasSuffix(p, " --") {
			name = strings.TrimSuffix(p, " --")
			files[name] = ""
			continue
		}
		if name != "" {
			files[name] += line
		}
	}
	return files
}

func TestParseTxtar(t *testing.T) {
	got := parseTxtar("comment\n-- a/b.json --\n{}\n-- empty --\n-- c --\n1\n2\n")
	want := map[string]string{"a/b.json": "{}\n", "empty": "", "c": "1\n2\n"}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for name, content := range want {
		if got[name] != content {
			t.Errorf("%s: got %q, want %q", name, got[name], content)
		}
	}
}

// TestAdvisories_Fixtures scans each fixture and requires every listed rule at
// exactly the listed severity. Other rules may fire as well: a fixture is a
// whole config, and the website only claims the listed ones.
func TestAdvisories_Fixtures(t *testing.T) {
	used := map[string]bool{}
	for _, a := range loadAdvisories(t) {
		path := filepath.Join(advisoryTxtars, advisorySlug(a.ID)+".txtar")
		if len(a.Rules) == 0 {
			if _, err := os.Stat(path); err == nil {
				t.Errorf("%s: an entry without rules has no fixture", a.ID)
			}
			continue
		}
		used[filepath.Base(path)] = true
		t.Run(a.ID, func(t *testing.T) {
			b, err := os.ReadFile(path) // #nosec G304 -- fixture in this repository
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			files := parseTxtar(string(b))
			if len(files) == 0 {
				t.Fatal("fixture has no files")
			}
			for name, content := range files {
				mustWrite(t, filepath.Join(dir, filepath.FromSlash(name)), content)
			}
			got := map[advisoryRule]bool{}
			for _, f := range scanFindings(t, "--claude-version", advisoryClaudeVersion, dir) {
				got[advisoryRule{f.RuleID, string(f.Severity)}] = true
			}
			for _, r := range a.Rules {
				if !got[r] {
					t.Errorf("%s did not report %s, got %v", r.Rule, r.Severity, got)
				}
			}
		})
	}
	entries, err := os.ReadDir(advisoryTxtars)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !used[e.Name()] {
			t.Errorf("%s: no advisory uses this fixture", e.Name())
		}
	}
}

// TestAdvisories_RuleDocs links the list and the rule docs in both directions:
// a rule an entry names must cite the advisory in its doc, and an advisory a
// rule doc cites must be in the list and name that rule. Campaigns have no id a
// doc could cite, so they are left out.
func TestAdvisories_RuleDocs(t *testing.T) {
	docs, err := filepath.Glob(filepath.Join(advisoryDocs, "*.md"))
	if err != nil || len(docs) == 0 {
		t.Fatalf("no rule docs: %v", err)
	}
	text := map[string]string{}
	for _, doc := range docs {
		b, err := os.ReadFile(doc) // #nosec G304 -- rule docs in this repository
		if err != nil {
			t.Fatal(err)
		}
		text[strings.TrimSuffix(filepath.Base(doc), ".md")] = string(b)
	}
	byID := map[string]advisory{}
	for _, a := range loadAdvisories(t) {
		if a.Kind != "cve" {
			continue
		}
		for _, id := range append([]string{a.ID}, a.Aliases...) {
			byID[id] = a
		}
		for rule := range advisoryRuleIDs(a) {
			cited := false
			for _, id := range append([]string{a.ID}, a.Aliases...) {
				cited = cited || strings.Contains(text[rule], id)
			}
			if !cited {
				t.Errorf("%s names %s, but docs/rules/%s.md does not cite it", a.ID, rule, rule)
			}
		}
	}
	for doc, content := range text {
		for _, id := range advisoryIDRe.FindAllString(content, -1) {
			a, ok := byID[id]
			if !ok {
				t.Errorf("docs/rules/%s.md cites %s, which is not in docs/advisories.yml", doc, id)
				continue
			}
			if doc != "README" && !advisoryRuleIDs(a)[doc] {
				t.Errorf("docs/rules/%s.md cites %s, but its entry names neither rule nor related %s", doc, id, doc)
			}
		}
	}
}
