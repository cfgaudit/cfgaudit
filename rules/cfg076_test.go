package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG076_BroadRoot_Error(t *testing.T) {
	for _, root := range []string{"/", "~", "~/", "$HOME", "${HOME}", "/*", "~/*", `C:\`, "C:/", "C:"} {
		j := `{"s":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","` +
			strings.ReplaceAll(root, `\`, `\\`) + `"]}}`
		f := CFG076.Check(mcpTarget(t, j))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("root %q: expected 1 Error, got %+v", root, f)
		}
	}
}

func TestCFG076_ParentTraversal_Warn(t *testing.T) {
	for _, p := range []string{"..", "../", "../..", "~/.."} {
		j := `{"s":{"command":"srv","args":["` + p + `"]}}`
		f := CFG076.Check(mcpTarget(t, j))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("traversal %q: expected 1 Warn, got %+v", p, f)
		}
	}
}

func TestCFG076_FlagValueForms(t *testing.T) {
	// --flag=/ (value after '='), and --root / (value as next positional arg).
	for _, j := range []string{
		`{"s":{"command":"srv","args":["--root=/"]}}`,
		`{"s":{"command":"srv","args":["--root","/"]}}`,
		`{"s":{"command":"srv","args":["--dir=$HOME"]}}`,
	} {
		f := CFG076.Check(mcpTarget(t, j))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("config %s: expected 1 Error, got %+v", j, f)
		}
	}
}

func TestCFG076_Benign_NoFinding(t *testing.T) {
	benign := []string{
		// scoped directories
		`{"s":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/srv/project"]}}`,
		`{"s":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","./data","~/projects/app"]}}`,
		// package spec and flags only — no path arg
		`{"s":{"command":"npx","args":["-y","@modelcontextprotocol/server-git","--repository","/srv/repo"]}}`,
		`{"s":{"command":"node","args":["server.js","--port","8080"]}}`,
		// a path that merely starts under home/root but is scoped
		`{"s":{"command":"srv","args":["/home/alice/work"]}}`,
	}
	for _, j := range benign {
		if f := CFG076.Check(mcpTarget(t, j)); len(f) != 0 {
			t.Errorf("benign %s: expected no finding, got %+v", j, f)
		}
	}
}

func TestCFG076_PackageSpecNotFlagged(t *testing.T) {
	// The scoped package name is positional but must never be read as a broad root.
	if f := CFG076.Check(mcpTarget(t, `{"s":{"command":"npx","args":["@scope/server-filesystem"]}}`)); len(f) != 0 {
		t.Errorf("expected no finding for package spec, got %+v", f)
	}
}

func TestCFG076_NoServers_NoFinding(t *testing.T) {
	if f := CFG076.Check(settingsTarget(t, `{"permissions":{"deny":["Read(.env)"]}}`)); len(f) != 0 {
		t.Errorf("expected no finding without MCP servers, got %+v", f)
	}
}

func TestCFG076_UserScope_AddsNote(t *testing.T) {
	tgt := mcpTarget(t, `{"s":{"command":"srv","args":["/"]}}`)
	tgt.Scope = finding.ScopeUser
	f := CFG076.Check(tgt)
	if len(f) != 1 || !strings.Contains(f[0].Message, "user-global scope") {
		t.Errorf("expected user-scope note, got %+v", f)
	}
}
