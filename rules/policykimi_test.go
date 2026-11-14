// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func kimiPolicyTarget(deny, forbid config.PolicyRules, rules ...string) *Target {
	var rs []parser.KimiPermissionRule
	for _, r := range rules {
		decision, pattern, _ := strings.Cut(r, " ")
		rs = append(rs, parser.KimiPermissionRule{Decision: decision, Pattern: pattern})
	}
	return &Target{PolicyAgent: "kimi-code", PolicyDeny: deny, PolicyForbid: forbid, PolicyFile: ".kimi-code/local.toml", PolicyKimiRules: rs}
}

// Each category of policy.deny against .kimi-code/local.toml rules, read as
// Kimi Code 2.6.2 reads them (#1731).
func TestCFG025_KimiDeny1731(t *testing.T) {
	for _, tc := range []struct {
		name  string
		deny  config.PolicyRules
		rules []string
		want  int
	}{
		{"spelled command rule", config.PolicyRules{Commands: []string{"git push"}}, []string{"deny Bash(git push{, *, */**})"}, 0},
		{"three command rules", config.PolicyRules{Commands: []string{"git push"}}, []string{"deny Bash(git push)", "deny Bash(git push *)", "deny Bash(git push */**)"}, 0},
		{"whole tool", config.PolicyRules{Commands: []string{"git push"}}, []string{"deny Bash"}, 0},
		{"any tool", config.PolicyRules{Commands: []string{"git push"}}, []string{"deny *"}, 0},
		// * stops at a slash: git push origin feature/x runs.
		{"star misses a slash", config.PolicyRules{Commands: []string{"git push"}}, []string{"deny Bash(git push*)"}, 1},
		{"Bash(*) misses a slash", config.PolicyRules{Commands: []string{"git push"}}, []string{"deny Bash(*)"}, 1},
		{"ask is no deny", config.PolicyRules{Commands: []string{"git push"}}, []string{"ask Bash"}, 1},
		{"no rules", config.PolicyRules{Commands: []string{"git push"}}, nil, 1},
		{"read anywhere", config.PolicyRules{Read: []string{"**/.env"}}, []string{"deny Read(**/.env)"}, 0},
		{"read root only", config.PolicyRules{Read: []string{"**/.env"}}, []string{"deny Read(.env)"}, 1},
		{"read home", config.PolicyRules{Read: []string{"~/.ssh/**"}}, []string{"deny Read(~/.ssh/**)"}, 0},
		{"read ** skips dot folders", config.PolicyRules{Read: []string{"~/.ssh/**"}}, []string{"deny Read(**)"}, 1},
		{"write both tools", config.PolicyRules{Write: []string{"src/generated/**"}}, []string{"deny {Write,Edit}(src/generated/**)"}, 0},
		{"write Edit only", config.PolicyRules{Write: []string{"src/generated/**"}}, []string{"deny Edit(src/generated/**)"}, 1},
		{"write absolute", config.PolicyRules{Write: []string{"src/generated/**"}}, []string{"deny Write(/repo/src/generated/**)", "deny Edit(./src/generated/**)"}, 0},
		{"fetch subdomains", config.PolicyRules{Fetch: []string{"*.example.com"}}, []string{"deny FetchURL(*://*.example.com/**)"}, 0},
		{"fetch one level", config.PolicyRules{Fetch: []string{"*.example.com"}}, []string{"deny FetchURL(https://*.example.com/*)"}, 1},
		{"fetch whole tool", config.PolicyRules{Fetch: []string{"example.com"}}, []string{"deny FetchURL"}, 0},
		{"mcp tool", config.PolicyRules{MCPTools: []string{"github:delete_*"}}, []string{"deny mcp__github__delete_*"}, 0},
		{"mcp server", config.PolicyRules{MCPTools: []string{"github:delete_*"}}, []string{"deny mcp__github__*"}, 0},
		{"mcp with argument never matches", config.PolicyRules{MCPTools: []string{"github:delete_*"}}, []string{"deny mcp__github__*(x)"}, 1},
		{"negated argument", config.PolicyRules{Commands: []string{"git push"}}, []string{"deny Bash(!npm test*)"}, 0},
		{"broken pattern", config.PolicyRules{Commands: []string{"git push"}}, []string{"deny Bash(git push"}, 1},
	} {
		f := CFG025.Check(kimiPolicyTarget(tc.deny, config.PolicyRules{}, tc.rules...))
		if len(f) != tc.want {
			t.Errorf("%s: want %d findings, got %+v", tc.name, tc.want, f)
		}
	}
}

// The suggested rule is one that covers the entry, and the message names the
// call that gets through.
func TestCFG025_KimiSpell1731(t *testing.T) {
	deny := config.PolicyRules{Commands: []string{"git push"}, Read: []string{"**/.env", "~/.ssh/**"}, Write: []string{"src/generated/**"},
		Fetch: []string{"*.example.com"}, MCPTools: []string{"github:delete_*"}}
	f := CFG025.Check(kimiPolicyTarget(deny, config.PolicyRules{}, "deny Bash(git push*)"))
	if len(f) != 6 {
		t.Fatalf("want 6 findings, got %+v", f)
	}
	if !strings.Contains(f[0].Message, `Bash on "git push origin feature/x"`) || !strings.Contains(f[0].Message, `pattern = "Bash(git push{, *, */**})"`) {
		t.Errorf("commands message: %s", f[0].Message)
	}
	if !strings.Contains(f[2].Message, `Read on "~/.ssh/probe"`) {
		t.Errorf("home message: %s", f[2].Message)
	}
	var rules []string
	for _, c := range policyCategories {
		for _, v := range c.entries(deny) {
			rules = append(rules, "deny "+kimiSpell(c.key, v))
		}
	}
	if f := CFG025.Check(kimiPolicyTarget(deny, config.PolicyRules{}, rules...)); len(f) != 0 {
		t.Errorf("the spelled rules %v leave %+v", rules, f)
	}
	if got := kimiSpell("commands", "make [x]"); got != `Bash(make \[x\]{, *, */**})` {
		t.Errorf("escape: %s", got)
	}
}

// forbid-allow: an allow rule that approves what the entry names, unless a
// deny rule, which Kimi checks first, refuses it.
func TestCFG025_KimiForbidAllow1731(t *testing.T) {
	for _, tc := range []struct {
		name   string
		forbid config.PolicyRules
		rules  []string
		want   int
	}{
		{"allow whole tool", config.PolicyRules{Commands: []string{"curl"}}, []string{"allow Bash"}, 1},
		{"allow prefix", config.PolicyRules{Commands: []string{"git push"}}, []string{"allow Bash(git push*)"}, 1},
		{"allow narrower", config.PolicyRules{Commands: []string{"git push"}}, []string{"allow Bash(git push --tags*)"}, 1},
		{"narrower but denied", config.PolicyRules{Commands: []string{"git push"}}, []string{"deny Bash(git push{, *, */**})", "allow Bash(git push --tags*)"}, 0},
		{"deny first", config.PolicyRules{Commands: []string{"curl"}}, []string{"allow Bash", "deny Bash(curl{, *, */**})"}, 0},
		{"other command", config.PolicyRules{Commands: []string{"curl"}}, []string{"allow Bash(npm test*)"}, 0},
		{"mcp", config.PolicyRules{MCPTools: []string{"github:*"}}, []string{"allow mcp__github__*"}, 1},
		{"read", config.PolicyRules{Read: []string{"**/.env"}}, []string{"allow Read"}, 1},
	} {
		f := CFG025.Check(kimiPolicyTarget(config.PolicyRules{}, tc.forbid, tc.rules...))
		if len(f) != tc.want {
			t.Errorf("%s: want %d findings, got %+v", tc.name, tc.want, f)
		}
	}
}

func TestKimiLocalIgnored1731(t *testing.T) {
	for _, tc := range []struct {
		gitignore string
		want      bool
	}{
		{".kimi-code/local.toml\n", true},
		{".kimi-code/\n", true},
		{"local.toml\n", true},
		{"node_modules/\n", false},
		// Git cannot re-include a file of an ignored folder.
		{".kimi-code/\n!.kimi-code/local.toml\n", true},
		{".kimi-code/*\n!.kimi-code/local.toml\n", false},
	} {
		if got := KimiLocalIgnored([]byte(tc.gitignore)); got != tc.want {
			t.Errorf("%q: got %v", tc.gitignore, got)
		}
	}
}

// The parts of the matcher the policy table does not reach: an extglob is not
// modelled and matches nothing, paths compare without case, ~ alone is the
// home directory, and a plain path entry is one probe.
func TestKimiMatcherEdges1731(t *testing.T) {
	if kimiGlob("ab", "a*(b)", false) {
		t.Error("extglob")
	}
	if !kimiRuleMatches("Read(/REPO/.ENV)", "Read", kimiRepo+"/.env", true) {
		t.Error("nocase path")
	}
	if !kimiRuleMatches("Read(~)", "Read", kimiHome, true) {
		t.Error("~ alone")
	}
	if got := kimiPathProbes("config/*.json"); len(got) != 1 || got[0] != kimiRepo+"/config/probe.json" {
		t.Errorf("plain path: %v", got)
	}
	if kimiRuleMatches("(x)", "Bash", "x", false) {
		t.Error("empty tool name")
	}
	if !kimiInClass("a-c", 'b') || kimiInClass("a-c", 'd') || !kimiInClass("xy", 'y') {
		t.Error("class")
	}
}
