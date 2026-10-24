// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/version"
	"github.com/cfgaudit/cfgaudit/rules"
)

// triggerExample is one code fence under a rule doc's "Trigger example"
// heading whose info string names the file it belongs in (#781):
//
//	```json path=.claude/settings.json version=2.1.300
type triggerExample struct {
	path    string // where the fence content goes, relative to the project
	version string // Claude Code version for the gated rules; empty runs all
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

// fenceInfo reads path= and version= from a fence info string; the first word
// is the language and is not needed.
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
		}
	}
	return ex
}

// TestRuleDocTriggerExamples writes each annotated trigger example of each rule
// doc into an empty project and checks that the rule fires on it (#781), so a
// rule change that leaves its doc example behind fails here.
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
		for i, ex := range triggerExamples(string(b)) {
			annotated++
			t.Run(id+"/"+ex.path, func(t *testing.T) {
				if filepath.IsAbs(ex.path) || strings.Contains(ex.path, "..") {
					t.Fatalf("example %d: path %q must stay inside the project", i+1, ex.path)
				}
				dir := t.TempDir()
				mustWrite(t, filepath.Join(dir, filepath.FromSlash(ex.path)), ex.content)
				var detected *version.Version
				if ex.version != "" {
					v, err := version.Parse(ex.version)
					if err != nil {
						t.Fatalf("example %d: version %q: %v", i+1, ex.version, err)
					}
					detected = &v
				}
				// The targets run() scans, minus --user and --plugins: a
				// marketplace.json in .claude-plugin/ makes dir a plugin root.
				targets, err := buildTargets(dir, false)
				if err != nil {
					t.Fatalf("buildTargets: %v", err)
				}
				pluginTargets, err := buildPluginTargets(dir, "", false)
				if err != nil {
					t.Fatalf("buildPluginTargets: %v", err)
				}
				targets = append(targets, dropDuplicateInstructions(targets, pluginTargets)...)
				var got []string
				for _, tg := range targets {
					for _, f := range rules.Run(tg, detected, nil) {
						if f.RuleID == id {
							return
						}
						got = append(got, f.RuleID)
					}
				}
				t.Errorf("example %d in docs/rules/%s.md (%s) does not trigger %s; findings: %v", i+1, id, ex.path, id, got)
			})
		}
	}
	if annotated == 0 {
		t.Error("no rule doc has an annotated trigger example")
	}
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
