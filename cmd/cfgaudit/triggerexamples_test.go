// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/version"
	"github.com/cfgaudit/cfgaudit/rules"
)

// triggerExample is one code fence under a rule doc's "Trigger example"
// heading whose info string names the file it belongs in (#781):
//
//	```json path=.claude/settings.json version=2.1.300
//
// Fences that share a group= belong to one example made of several files and
// are scanned together (#1862):
//
//	```json path=.claude/settings.json group=implant
//	```text path=.tooling/start.mjs group=implant
type triggerExample struct {
	path    string // where the fence content goes, relative to the project
	version string // Claude Code version for the gated rules; empty runs all
	group   string // fences with the same non-empty group are scanned together
	content string
}

// triggerExamples returns the annotated fences in the Trigger example section
// of a rule doc. A fence without path= is not one. The section ends at the
// next level-2 heading outside a fence: an example CLAUDE.md can have its own
// "## " lines.
func triggerExamples(doc string) []triggerExample {
	var (
		out     []triggerExample
		in      bool            // inside the Trigger example section
		fence   *triggerExample // the fence being read, nil outside one
		inOther bool            // inside a fence without path=
		body    strings.Builder
	)
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case fence != nil || inOther:
			if trimmed == "```" {
				if fence != nil {
					fence.content = body.String()
					out = append(out, *fence)
				}
				fence, inOther = nil, false
				body.Reset()
				continue
			}
			body.WriteString(line + "\n")
		case strings.HasPrefix(line, "## "):
			in = trimmed == "## Trigger example" || trimmed == "## Trigger examples"
		case strings.HasPrefix(trimmed, "```"):
			ex := fenceInfo(strings.TrimPrefix(trimmed, "```"))
			if in && ex.path != "" {
				fence = &ex
			} else {
				inOther = true
			}
		}
	}
	return out
}

// fenceInfo reads path=, version= and group= from a fence info string; the
// first word is the language and is not needed.
func fenceInfo(info string) triggerExample {
	var ex triggerExample
	for _, field := range strings.Fields(info) {
		key, val, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "path":
			ex.path = val
		case "version":
			ex.version = val
		case "group":
			ex.group = val
		}
	}
	return ex
}

// TestRuleDocTriggerExamples writes each annotated trigger example of each rule
// doc into an empty project and checks that the rule fires on it (#781), so a
// rule change that leaves its doc example behind fails here. Fences that share
// a group= are written into one project and scanned together, for a rule whose
// trigger needs several files (#1862).
func TestRuleDocTriggerExamples(t *testing.T) {
	docs, err := filepath.Glob(filepath.Join("..", "..", "docs", "rules", "CFG*.md"))
	if err != nil || len(docs) == 0 {
		t.Fatalf("no rule docs found: %v", err)
	}
	annotated := 0
	for _, doc := range docs {
		id := strings.TrimSuffix(filepath.Base(doc), ".md")
		b, err := os.ReadFile(doc) // #nosec G304 -- rule docs in this repository
		if err != nil {
			t.Fatal(err)
		}
		examples := triggerExamples(string(b))
		annotated += len(examples)
		// Ungrouped fences each stand alone; fences sharing a group= form one
		// multi-file example scanned together, in document order.
		var solo []triggerExample
		var groups []string
		grouped := map[string][]triggerExample{}
		for _, ex := range examples {
			if ex.group == "" {
				solo = append(solo, ex)
				continue
			}
			if _, seen := grouped[ex.group]; !seen {
				groups = append(groups, ex.group)
			}
			grouped[ex.group] = append(grouped[ex.group], ex)
		}
		for i, ex := range solo {
			t.Run(id+"/"+ex.path, func(t *testing.T) {
				runTriggerExample(t, id, i+1, []triggerExample{ex})
			})
		}
		for _, name := range groups {
			t.Run(id+"/group:"+name, func(t *testing.T) {
				runTriggerExample(t, id, 0, grouped[name])
			})
		}
	}
	if annotated == 0 {
		t.Error("no rule doc has an annotated trigger example")
	}
}

// runTriggerExample writes the files of one example into an empty project and
// asserts that id fires. A single-file example passes one fence; a grouped
// example passes the fences that share its group=, all written before the scan.
func runTriggerExample(t *testing.T, id string, num int, exs []triggerExample) {
	t.Helper()
	dir := t.TempDir()
	var detected *version.Version
	for _, ex := range exs {
		if filepath.IsAbs(ex.path) || strings.Contains(ex.path, "..") {
			t.Fatalf("example path %q must stay inside the project", ex.path)
		}
		mustWrite(t, filepath.Join(dir, filepath.FromSlash(ex.path)), ex.content)
		if ex.version != "" && detected == nil {
			v, err := version.Parse(ex.version)
			if err != nil {
				t.Fatalf("version %q: %v", ex.version, err)
			}
			detected = &v
		}
	}
	fired, got := scanForRule(t, dir, id, detected)
	if fired {
		return
	}
	where := "docs/rules/" + id + ".md"
	if num > 0 {
		t.Errorf("example %d in %s (%s) does not trigger %s; findings: %v", num, where, exs[0].path, id, got)
	} else {
		var paths []string
		for _, ex := range exs {
			paths = append(paths, ex.path)
		}
		t.Errorf("grouped example in %s (%s) does not trigger %s; findings: %v", where, strings.Join(paths, ", "), id, got)
	}
}

// scanForRule scans dir the way run() does, minus --user and --plugins, and
// reports whether id appears in the findings (with the other rule IDs seen).
func scanForRule(t *testing.T, dir, id string, detected *version.Version) (bool, []string) {
	t.Helper()
	// A marketplace.json in .claude-plugin/ makes dir a plugin root.
	targets, err := buildTargets(dir, false)
	if err != nil {
		t.Fatalf("buildTargets: %v", err)
	}
	// An example that is a .cfgaudit.yml (CFG118) is read as the project config.
	cfg, _, err := loadConfig("", dir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	targets = attachPolicy(dir, targets, cfg)
	pluginTargets, err := buildPluginTargets(dir, "", false)
	if err != nil {
		t.Fatalf("buildPluginTargets: %v", err)
	}
	targets = append(targets, dropDuplicateInstructions(targets, pluginTargets)...)
	var got []string
	for _, tg := range targets {
		for _, f := range rules.Run(tg, detected, nil) {
			if f.RuleID == id {
				return true, nil
			}
			got = append(got, f.RuleID)
		}
	}
	return false, got
}

// exampleExceptions lists registered rules whose trigger cannot be written as
// plain-text files into a project, so TestRuleDocTriggerExamples cannot run it.
// Each value says why and names the Go test that covers the rule instead. A
// rule that gains an executable trigger example must be dropped from this map:
// TestEveryRuleHasTriggerExampleOrException fails on an entry whose rule now has
// one, and on an entry that names no registered rule.
var exampleExceptions = map[string]string{
	"CFG024": "invisible/zero-width or variation-selector codepoints only carry their meaning as real bytes, not as text in a doc fence; rules/cfg024_test.go (TestCFG024_SneakyBitsRun) covers it",
	"CFG045": "ShellCheck is an external tool: the rule is inert unless --shellcheck is set and the shellcheck binary is on PATH, so a file alone cannot trigger it; rules/cfg045_test.go (TestCFG045_HappyPath) covers it",
	"CFG111": "the trigger is a zero-width codepoint hidden inside a permissions entry or matcher, which only works as real bytes; rules/cfg111_test.go (TestCFG111_HiddenCharacters) covers it",
	"CFG115": "the trigger is a committed symlink whose target leaves the repo, which needs real filesystem link metadata, not file content; rules/cfg115_test.go (TestCFG115_SensitiveTargets) covers it",
	"CFG122": "the scan target is a binary archive (.zip/.tar.gz) carrying a .git entry, a tool binary or a link, which cannot be written as a text fence; rules/cfg122_test.go (TestCFG122_ArchiveOnly1002) covers it",
	"CFG129": "the trigger is a committed Python .pyc, a binary bytecode file the scanner classifies by its header, not text; rules/cfg129_test.go (TestCFG129_Bytecode1398) covers it",
}

// TestEveryRuleHasTriggerExampleOrException requires every registered rule to
// carry at least one executable path= trigger example in its doc, or an entry
// in exampleExceptions that points at the test covering it (#1862). This is the
// guard the issue asks for: drop the path= from a rule's only example and the
// rule falls out of the covered set, so this test fails naming it.
func TestEveryRuleHasTriggerExampleOrException(t *testing.T) {
	have := rulesWithTriggerExample(t)
	registered := map[string]bool{}
	var ids []string
	for _, r := range rules.All {
		id := r.ID()
		registered[id] = true
		ids = append(ids, id)
		if have[id] && exampleExceptions[id] != "" {
			t.Errorf("%s has an executable trigger example; remove its exampleExceptions entry", id)
		}
	}
	for _, id := range uncoveredRules(have, exampleExceptions, ids) {
		t.Errorf("%s has no executable `path=` trigger example in docs/rules/%s.md and no exampleExceptions entry. "+
			"Add a runnable example under \"## Trigger example\" (annotate the fence with path=..., and group=... for a multi-file example), "+
			"or add an exception naming the test that covers it.", id, id)
	}
	for id := range exampleExceptions {
		if !registered[id] {
			t.Errorf("exampleExceptions names %q, which is not a registered rule", id)
		}
	}
}

// uncoveredRules returns the ids that have neither an executable trigger example
// (have[id]) nor an exampleExceptions entry, sorted.
func uncoveredRules(have map[string]bool, exceptions map[string]string, ids []string) []string {
	var missing []string
	for _, id := range ids {
		if !have[id] && exceptions[id] == "" {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	return missing
}

// TestTriggerExampleGuard is the guard the issue asks for (#1862): drop the
// path= from a rule's only example, so it has no executable example, and unless
// it is a documented exception it is reported as uncovered, by name.
func TestTriggerExampleGuard(t *testing.T) {
	ids := []string{"CFG001", "CFG002", "CFG003"}
	have := map[string]bool{"CFG001": true, "CFG002": true}
	exceptions := map[string]string{"CFG003": "covered by its integration test"}
	if got := uncoveredRules(have, exceptions, ids); len(got) != 0 {
		t.Fatalf("all covered, got %v", got)
	}
	// CFG002 loses its path= annotation: now it has no example and no exception.
	delete(have, "CFG002")
	if got := uncoveredRules(have, exceptions, ids); len(got) != 1 || got[0] != "CFG002" {
		t.Fatalf("dropping CFG002's example should name it, got %v", got)
	}
}

// rulesWithTriggerExample returns the set of rule IDs whose doc carries at least
// one annotated path= trigger example.
func rulesWithTriggerExample(t *testing.T) map[string]bool {
	t.Helper()
	docs, err := filepath.Glob(filepath.Join("..", "..", "docs", "rules", "CFG*.md"))
	if err != nil || len(docs) == 0 {
		t.Fatalf("no rule docs found: %v", err)
	}
	have := map[string]bool{}
	for _, doc := range docs {
		b, err := os.ReadFile(doc) // #nosec G304 -- rule docs in this repository
		if err != nil {
			t.Fatal(err)
		}
		if len(triggerExamples(string(b))) > 0 {
			have[strings.TrimSuffix(filepath.Base(doc), ".md")] = true
		}
	}
	return have
}

func TestTriggerExamplesParsing(t *testing.T) {
	doc := "# X\n\n```json path=early.json\n{}\n```\n\n## Trigger example\n\n```json path=.mcp.json version=2.1.300\n{}\n```\n\n" +
		"```json\n{\"skip\": true}\n```\n\n```markdown path=CLAUDE.md\n## Notes\nbody\n```\n\n## Safe alternative\n\n```json path=a.json\n{}\n```\n"
	got := triggerExamples(doc)
	if len(got) != 2 || got[0].path != ".mcp.json" || got[0].version != "2.1.300" || got[0].content != "{}\n" ||
		got[1].path != "CLAUDE.md" || got[1].content != "## Notes\nbody\n" {
		t.Fatalf("triggerExamples = %+v", got)
	}
}

func TestTriggerExamplesGrouping(t *testing.T) {
	doc := "## Trigger example\n\n```json path=.claude/settings.json group=implant\n{}\n```\n\n" +
		"```text path=hook.sh group=implant\nbody\n```\n"
	got := triggerExamples(doc)
	if len(got) != 2 || got[0].group != "implant" || got[1].group != "implant" ||
		got[0].path != ".claude/settings.json" || got[1].path != "hook.sh" {
		t.Fatalf("triggerExamples = %+v", got)
	}
}
