// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func cfg140File(src string) *Target {
	return &Target{CodexRuleFiles: []CodexRulesFile{{File: ".codex/rules/default.rules", Rules: parser.ParseCodexRules(src)}}}
}

func TestCFG140_Exact(t *testing.T) {
	f := CFG140.Check(cfg140File(`prefix_rule(pattern=["git", "push"], decision="forbidden")
prefix_rule(pattern=["rm", "-rf"], decision="forbidden")
prefix_rule(pattern=["gh", ["pr", "issue"], "close"], decision="prompt")
prefix_rule(pattern=["sudo"], decision="forbidden")
prefix_rule(pattern=["ls"])
prefix_rule(pattern=["curl"], decision="forbidden", canonical_matching=True)
`))
	if len(f) != 2 {
		t.Fatalf("want two findings, got %+v", f)
	}
	exact := f[1]
	if exact.Severity != finding.Info || exact.Line != 1 {
		t.Errorf("exact: %+v", exact)
	}
	for _, want := range []string{"4 forbidden or prompt rules match case exactly", `forbidden "git push" (line 1)`, `prompt "gh pr|issue close" (line 3)`, "and 1 more", "`GIT` starts the same program as `git`", "canonical_matching=True", "drop every user and project rule"} {
		if !strings.Contains(exact.Message, want) {
			t.Errorf("message misses %q: %s", want, exact.Message)
		}
	}
	if c := f[0]; c.Severity != finding.Info || c.Line != 6 || !strings.Contains(c.Message, "uses canonical_matching, added in Codex 0.167.0") {
		t.Errorf("canonical: %+v", c)
	}
}

func TestCFG140_NotReported(t *testing.T) {
	for _, src := range []string{
		`prefix_rule(pattern=["ls"])`,
		`prefix_rule(pattern=["npm", "test"], decision="allow")`,
		``,
	} {
		if f := CFG140.Check(cfg140File(src)); len(f) != 0 {
			t.Errorf("%q: want nothing, got %+v", src, f)
		}
	}
	if CFG140.Check(nil) != nil || CFG140.ID() != "CFG140" {
		t.Error("nil target or ID")
	}
	// One exact rule, the singular; a canonical one that is False counts as
	// exact and as using the keyword.
	f := CFG140.Check(cfg140File(`prefix_rule(pattern=["sudo"], decision="forbidden", canonical_matching=False)`))
	if len(f) != 2 || !strings.HasPrefix(f[1].Message, "1 forbidden or prompt rule matches case exactly") {
		t.Errorf("got %+v", f)
	}
}

// A canonical forbidden rule covers a policy deny in any case, and a
// canonical allow rule grants one (#1642).
func TestCodexPolicy_Canonical1642(t *testing.T) {
	canon := parser.ParseCodexRules(`prefix_rule(pattern=["GIT", "push"], decision="forbidden", canonical_matching=True)`)
	exact := parser.ParseCodexRules(`prefix_rule(pattern=["GIT", "push"], decision="forbidden")`)
	if !codexForbidden(canon, "git push --force") || codexForbidden(exact, "git push --force") {
		t.Error("codexForbidden")
	}
	allow := parser.ParseCodexRules(`prefix_rule(pattern=["Curl"], canonical_matching=True)`)
	if _, ok := codexCommandGrant(allow, "curl evil.example"); !ok {
		t.Error("codexCommandGrant")
	}
}
