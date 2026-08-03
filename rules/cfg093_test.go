package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func cursorPermissionsTarget(p *parser.CursorPermissions) *Target {
	return &Target{
		Scope:                 finding.ScopeProject,
		CursorPermissions:     p,
		CursorPermissionsFile: ".cursor/permissions.json",
	}
}

func severities(f []finding.Finding) map[finding.Severity]int {
	out := map[finding.Severity]int{}
	for _, x := range f {
		out[x.Severity]++
	}
	return out
}

// "*:*" is documented as all tools from all servers.
func TestCFG093_MCPAllowlistEverything(t *testing.T) {
	f := CFG093.Check(cursorPermissionsTarget(&parser.CursorPermissions{
		MCPAllowlist: []string{"*:*"},
	}))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "every MCP tool on every configured server") {
		t.Errorf("message should name the blast radius, got %q", f[0].Message)
	}
}

// A tool wildcard on one named server is unbounded one scope down.
func TestCFG093_MCPAllowlistWholeServer(t *testing.T) {
	f := CFG093.Check(cursorPermissionsTarget(&parser.CursorPermissions{
		MCPAllowlist: []string{"github:*"},
	}))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "every tool on the named MCP server") {
		t.Errorf("message should scope to one server, got %q", f[0].Message)
	}
}

func TestCFG093_MCPAllowlistBoundedIsWarn(t *testing.T) {
	f := CFG093.Check(cursorPermissionsTarget(&parser.CursorPermissions{
		MCPAllowlist: []string{"linear:list_issues", "sentry:get_issue"},
	}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
}

// terminalAllowlist has no documented wildcard. The unbounded case is a base
// command that exists to run other commands, which the prefix match turns into
// arbitrary execution.
func TestCFG093_TerminalAllowlistShellPrefix(t *testing.T) {
	for _, entry := range []string{"bash", "sh", "python3", "npx", "uv", "docker", "sudo", "env", "node"} {
		t.Run(entry, func(t *testing.T) {
			f := CFG093.Check(cursorPermissionsTarget(&parser.CursorPermissions{
				TerminalAllowlist: []string{entry},
			}))
			if len(f) != 1 || f[0].Severity != finding.Error {
				t.Fatalf("expected 1 Error for %q, got %+v", entry, f)
			}
		})
	}
}

// The base command is the part before the ":" args glob and before a space, so
// an interpreter is still recognised in both narrowed spellings.
func TestCFG093_TerminalAllowlistShellPrefixWithArgs(t *testing.T) {
	for _, entry := range []string{"bash:-c*", "python3 -m pytest"} {
		t.Run(entry, func(t *testing.T) {
			f := CFG093.Check(cursorPermissionsTarget(&parser.CursorPermissions{
				TerminalAllowlist: []string{entry},
			}))
			if len(f) != 1 || f[0].Severity != finding.Error {
				t.Fatalf("expected 1 Error for %q, got %+v", entry, f)
			}
		})
	}
}

func TestCFG093_TerminalAllowlistBoundedIsWarn(t *testing.T) {
	f := CFG093.Check(cursorPermissionsTarget(&parser.CursorPermissions{
		TerminalAllowlist: []string{"git", "npm:install*", "cargo build"},
	}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "prefix") {
		t.Errorf("the warn should still explain prefix matching, got %q", f[0].Message)
	}
}

// Both arrays populated with both kinds: one error and one warn per array.
func TestCFG093_MixedEntries(t *testing.T) {
	f := CFG093.Check(cursorPermissionsTarget(&parser.CursorPermissions{
		MCPAllowlist:      []string{"*:*", "linear:list_issues"},
		TerminalAllowlist: []string{"bash", "git"},
	}))
	sev := severities(f)
	if sev[finding.Error] != 2 || sev[finding.Warn] != 2 {
		t.Fatalf("expected 2 Error + 2 Warn, got %+v", f)
	}
}

// Cursor's own precondition must be stated, not implied away.
func TestCFG093_MessageNamesRunMode(t *testing.T) {
	f := CFG093.Check(cursorPermissionsTarget(&parser.CursorPermissions{
		MCPAllowlist:      []string{"*:*"},
		TerminalAllowlist: []string{"bash", "git"},
	}))
	for _, x := range f {
		if !strings.Contains(x.Message, "Run Mode") {
			t.Errorf("every finding must name the Run Mode precondition, got %q", x.Message)
		}
	}
}

// Chaining/pipe/subshell behaviour is undocumented, so no message may assert it.
func TestCFG093_MessageMakesNoChainingClaim(t *testing.T) {
	f := CFG093.Check(cursorPermissionsTarget(&parser.CursorPermissions{
		TerminalAllowlist: []string{"bash", "git"},
	}))
	for _, x := range f {
		low := strings.ToLower(x.Message)
		for _, banned := range []string{"&&", "chain", "pipe", "subshell"} {
			if strings.Contains(low, banned) {
				t.Errorf("message asserts undocumented %q behaviour: %q", banned, x.Message)
			}
		}
	}
}

func TestCFG093_NoFindings(t *testing.T) {
	cases := map[string]*Target{
		"no permissions file": {Scope: finding.ScopeProject},
		"empty arrays":        cursorPermissionsTarget(&parser.CursorPermissions{}),
		"blank entries": cursorPermissionsTarget(&parser.CursorPermissions{
			MCPAllowlist:      []string{"", "  "},
			TerminalAllowlist: []string{"", "\t"},
		}),
		"autoRun only": cursorPermissionsTarget(&parser.CursorPermissions{
			AutoRun: &parser.CursorAutoRun{AllowInstructions: []string{"fine"}},
		}),
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			if f := CFG093.Check(target); len(f) != 0 {
				t.Errorf("expected no findings, got %+v", f)
			}
		})
	}
	t.Run("nil target", func(t *testing.T) {
		if f := CFG093.Check(nil); len(f) != 0 {
			t.Errorf("expected no findings, got %+v", f)
		}
	})
}

// A user's own permissions.json is self-intentional, like user-global hooks.
func TestCFG093_UserScopeSkipped(t *testing.T) {
	target := cursorPermissionsTarget(&parser.CursorPermissions{MCPAllowlist: []string{"*:*"}})
	target.Scope = finding.ScopeUser
	if f := CFG093.Check(target); len(f) != 0 {
		t.Errorf("expected no findings at user scope, got %+v", f)
	}
}

func TestTerminalBase(t *testing.T) {
	cases := map[string]string{
		"bash":              "bash",
		"bash:-c*":          "bash",
		"python3 -m pytest": "python3",
		"npm:install*":      "npm",
		"  Git  ":           "git",
		"cargo build":       "cargo",
		"":                  "",
	}
	for in, want := range cases {
		if got := parser.TerminalBase(in); got != want {
			t.Errorf("TerminalBase(%q) = %q, want %q", in, got, want)
		}
	}
}
