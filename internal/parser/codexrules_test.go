// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseCodexRules(t *testing.T) {
	got := ParseCodexRules(`# prefix_rule(pattern=["in", "comment"], decision="forbidden")
prefix_rule(pattern=["git", "push"], decision="forbidden")
prefix_rule(
    pattern = ["gh", ["pr", "issue"], "close"],  # alternatives
    decision = "prompt",
    justification = "it's (fine), really",
    match = [["gh", "pr", "close"], "gh issue close"],
)
prefix_rule(pattern=['curl'])
text = "prefix_rule(pattern=[\"in\", \"string\"])"
prefix_rule(pattern=names, decision="forbidden")
prefix_rule(decision="forbidden")
prefix_rule(pattern=["a", 3], decision="forbidden")
prefix_rule(pattern=[["a", 3]])
prefix_rule(pattern=[], decision="forbidden")
prefix_rule(pattern=["b"], decision=value)
prefix_rule(pattern=["esc\"aped"])
host_executable(name="git", paths=["/usr/bin/git"])
`)
	want := []CodexRule{
		{Pattern: [][]string{{"git"}, {"push"}}, Decision: "forbidden"},
		{Pattern: [][]string{{"gh"}, {"pr", "issue"}, {"close"}}, Decision: "prompt"},
		{Pattern: [][]string{{"curl"}}, Decision: "allow"},
		{Pattern: [][]string{{`esc"aped`}}, Decision: "allow"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

// A file cut off anywhere must end the scan, not hang or panic.
func TestParseCodexRules_Truncated(t *testing.T) {
	src := `prefix_rule(pattern=["a", ["b", "c"]], decision="forbidden", match=[["a", "b"]])` + "\n" + `"open`
	for i := range src {
		ParseCodexRules(src[:i])
	}
	if got := ParseCodexRules(`prefix_rule(pattern=["a"], other=(1, [2], {3}), # note
	decision="forbidden")`); len(got) != 1 || got[0].Decision != "forbidden" {
		t.Fatalf("got %+v", got)
	}
}

func TestCodexRule_Matching(t *testing.T) {
	r := CodexRule{Pattern: [][]string{{"gh"}, {"pr", "issue"}}}
	for cmd, want := range map[string]bool{"gh pr": true, "gh issue close": true, "gh": false, "gh repo": false} {
		if got := r.MatchesPrefix(strings.Fields(cmd)); got != want {
			t.Errorf("MatchesPrefix %q: got %v", cmd, got)
		}
	}
	for prefix, want := range map[string]bool{"gh": true, "gh pr": true, "gh pr x": false, "gh repo": false} {
		if got := r.Under(strings.Fields(prefix)); got != want {
			t.Errorf("Under %q: got %v", prefix, got)
		}
	}
}
