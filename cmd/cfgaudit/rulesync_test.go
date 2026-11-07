// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/config"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestRulesyncEntries(t *testing.T) {
	deny, forbid, skipped := rulesyncEntries(parser.RulesyncRules{
		"bash":                     {"git push *": "deny", "curl:*": "ask", "git *": "allow", "*": "deny", "rm * -rf": "deny"},
		"read":                     {".env": "deny", "credentials/**": "deny", "~/.ssh/**": "deny", "docs/**": "allow", "/etc/**": "deny", "x": "ask"},
		"edit":                     {"src/**": "deny"},
		"write":                    {"gen/**": "deny"},
		"webfetch":                 {"domain:example.com": "deny", "*.example.org": "deny", "https://a/*": "deny", "b.com": "ask"},
		"mcp__github__delete_repo": {"*": "deny"},
		"mcp__linear":              {"*": "ask"},
		"websearch":                {"*": "deny"},
		"grep":                     {"*": "allow"},
	})
	want := config.PolicyRules{
		Commands: []string{"git push"},
		Read:     []string{".env", "credentials/**", "~/.ssh/**"},
		Write:    []string{"src/**", "gen/**"},
		Fetch:    []string{"*.example.org", "example.com"},
		MCPTools: []string{"github:delete_repo"},
	}
	if !reflect.DeepEqual(deny, want) {
		t.Errorf("deny: %+v", deny)
	}
	if !reflect.DeepEqual(forbid, config.PolicyRules{Commands: []string{"curl"}, MCPTools: []string{"linear:*"}}) {
		t.Errorf("forbid: %+v", forbid)
	}
	if strings.Join(skipped, ",") != "bash *,bash rm * -rf,read /etc/**,webfetch https://a/*,websearch *" {
		t.Errorf("skipped: %q", skipped)
	}
}

func rulesyncFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	return policyFindings(t, runFixture(t, files))
}

func TestPolicy_Rulesync(t *testing.T) {
	// A tool block replaces the shared category for that agent only.
	got := rulesyncFindings(t, map[string]string{
		".cfgaudit.yml": "policy:\n  rulesync: true\n",
		".rulesync/permissions.jsonc": `{
			// the source
			"permission": {"bash": {"git push *": "deny"}},
			"claudecode": {"permission": {"bash": {"npm publish *": "deny"}}},
		}`,
		".claude/settings.json": `{"permissions":{"deny":["Bash(npm publish:*)"]}}`,
		".devin/config.json":    `{"permissions":{"deny":[]}}`,
	})
	if len(got) != 1 || !strings.HasPrefix(got[0], ".devin/config.json|CFG025|policy deny.commands \"git push\"") {
		t.Fatalf("got %q", got)
	}

	// Off by default, and the legacy path when no JSONC file exists.
	files := map[string]string{
		".rulesync/permissions.json": `{"permission":{"bash":{"git push *":"deny"}}}`,
		".devin/config.json":         `{"permissions":{"deny":[]}}`,
	}
	if got := rulesyncFindings(t, files); len(got) != 0 {
		t.Fatalf("no policy: %q", got)
	}
	files[".cfgaudit.yml"] = "policy:\n  rulesync: true\n"
	if got := rulesyncFindings(t, files); len(got) != 1 {
		t.Fatalf("legacy file: %q", got)
	}

	// JSONC wins over JSON.
	got = rulesyncFindings(t, map[string]string{
		".cfgaudit.yml":               "policy:\n  rulesync: true\n",
		".rulesync/permissions.jsonc": `{"permission":{}}`,
		".rulesync/permissions.json":  `{"permission":{"bash":{"git push *":"deny"}}}`,
		".devin/config.json":          `{"permissions":{"deny":[]}}`,
	})
	if len(got) != 0 {
		t.Fatalf("got %q", got)
	}

	// A broken or missing source leaves the policy as it was.
	if got := rulesyncFindings(t, map[string]string{
		".cfgaudit.yml":      "policy:\n  rulesync: true\n",
		".devin/config.json": `{}`,
	}); len(got) != 0 {
		t.Fatalf("got %q", got)
	}
	if got := rulesyncFindings(t, map[string]string{
		".cfgaudit.yml":               "policy:\n  rulesync: true\n",
		".rulesync/permissions.jsonc": `{`,
		".devin/config.json":          `{}`,
	}); len(got) != 0 {
		t.Fatalf("got %q", got)
	}
}

// Both sources apply: a contradiction is a finding on the Rulesync file, and a
// rule with no neutral form is listed.
func TestPolicy_RulesyncConflict(t *testing.T) {
	got := rulesyncFindings(t, map[string]string{
		".cfgaudit.yml": "policy:\n  rulesync: true\n  deny:\n    commands: [\"git push\"]\n    read: [\"secrets/**\"]\n    write: [\"src/**\"]\n",
		".rulesync/permissions.jsonc": `{"permission":{
			"bash":{"git push --tags":"allow","*":"deny"},
			"read":{"secrets/**":"allow"},
			"edit":{"src/**":"allow"}
		}}`,
	})
	want := []string{
		`.rulesync/permissions.jsonc|CFG025|policy deny.commands "git push" conflicts with the bash rule "git push --tags": allow in the Rulesync file`,
		`.rulesync/permissions.jsonc|CFG025|policy deny.read "secrets/**" conflicts with the read rule "secrets/**": allow in the Rulesync file`,
		`.rulesync/permissions.jsonc|CFG025|policy deny.write "src/**" conflicts with the edit rule "src/**": allow in the Rulesync file`,
		`.rulesync/permissions.jsonc|CFG118|these Rulesync rules have no agent-neutral form and are not checked: bash *`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s", strings.Join(got, "\n"))
	}
}

func TestRulesyncHelpers(t *testing.T) {
	for in, ok := range map[string]bool{"": false, "*": false, "git": true, "a *": true} {
		if _, got := rulesyncCommand(in); got != ok {
			t.Errorf("command %q: %v", in, got)
		}
	}
	for _, in := range []string{"", "/abs", "../up", "*", "**"} {
		if _, ok := rulesyncPath(in); ok {
			t.Errorf("path %q", in)
		}
	}
	s := &rulesyncSource{perms: &parser.RulesyncPermissions{
		Shared: parser.RulesyncRules{"bash": {"a": "deny"}},
		Tools:  map[string]parser.RulesyncRules{"cursor": {"bash": {"b": "deny"}}},
	}}
	if got := s.rulesFor("cursor-cli"); got["bash"]["b"] == "" {
		t.Errorf("got %+v", got)
	}
	if got := withRulesync(config.Policy{}, nil, "x"); !reflect.DeepEqual(got, config.Policy{}) {
		t.Errorf("got %+v", got)
	}
}
