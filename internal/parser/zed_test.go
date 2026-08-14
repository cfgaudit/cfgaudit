package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeZed(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestParseZedSettings_ContextServers(t *testing.T) {
	path := writeZed(t, `{
	  "theme": "One Dark",
	  "context_servers": {
	    "local": { "command": "some-command", "args": ["a", "b"], "env": {"K": "v"} },
	    "remote": { "url": "https://example.com/mcp", "headers": {"Authorization": "Bearer x"} }
	  }
	}`)
	zed, err := ParseZedSettings(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(zed.ContextServers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(zed.ContextServers))
	}
	if got := zed.ContextServers["local"].Command; got != "some-command" {
		t.Errorf("command = %q", got)
	}
	if got := zed.ContextServers["local"].Args; len(got) != 2 || got[0] != "a" {
		t.Errorf("args = %v", got)
	}
	if got := zed.ContextServers["remote"].URL; got != "https://example.com/mcp" {
		t.Errorf("url = %q", got)
	}
	if got := zed.ContextServers["remote"].Headers["Authorization"]; got != "Bearer x" {
		t.Errorf("header = %q", got)
	}
}

// Zed ships a heavily commented default settings file, so JSONC must decode.
func TestParseZedSettings_JSONC(t *testing.T) {
	path := writeZed(t, `{
	  // the assistant's MCP servers
	  "context_servers": {
	    "local": { "command": "x" }, // trailing comment
	  },
	}`)
	zed, err := ParseZedSettings(path)
	if err != nil {
		t.Fatalf("parse JSONC: %v", err)
	}
	if len(zed.ContextServers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(zed.ContextServers))
	}
}

func TestParseZedSettings_NoKey(t *testing.T) {
	path := writeZed(t, `{"theme": "One Dark"}`)
	zed, err := ParseZedSettings(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(zed.ContextServers) != 0 {
		t.Errorf("expected no servers, got %v", zed.ContextServers)
	}
}

func TestParseZedSettings_Malformed(t *testing.T) {
	path := writeZed(t, `{not json`)
	if _, err := ParseZedSettings(path); err == nil {
		t.Error("expected an error for malformed settings, got nil")
	}
}

func TestParseZedSettings_Missing(t *testing.T) {
	if _, err := ParseZedSettings(filepath.Join(t.TempDir(), "nope.json")); !os.IsNotExist(errUnwrap(err)) {
		t.Errorf("expected a not-exist error, got %v", err)
	}
}

// errUnwrap peels the fmt.Errorf wrapper so os.IsNotExist can see the cause.
func errUnwrap(err error) error {
	type unwrapper interface{ Unwrap() error }
	for {
		u, ok := err.(unwrapper)
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
}

// #467: the three ProjectSettingsContent fields that name an executable.
func TestZedSettings_CommandSites(t *testing.T) {
	path := writeZed(t, `{
      "terminal": {"shell": {"with_arguments": {"program": "zsh", "args": ["-l", "-c", "echo hi"]}},
                   "env": {"TOKEN": "x"}},
      "lsp": {"rust-analyzer": {"binary": {"path": "rust-analyzer", "arguments": ["--stdio"]}},
              "noop": {"settings": {"a": 1}}},
      "dap": {"CodeLLDB": {"binary": ".zed/codelldb", "args": ["--port", "1234"]}}
    }`)
	zed, err := ParseZedSettings(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sites := zed.CommandSites()
	if len(sites) != 3 {
		t.Fatalf("expected 3 sites, got %d: %+v", len(sites), sites)
	}
	// A shell keeps its arguments; a non-shell does not, because its argv goes to
	// execve rather than to an interpreter.
	if sites[0].Command != "zsh -l -c echo hi" {
		t.Errorf("shell command = %q", sites[0].Command)
	}
	if sites[1].Command != "rust-analyzer" {
		t.Errorf("lsp command = %q, argv must not be treated as shell text", sites[1].Command)
	}
	if sites[2].Command != ".zed/codelldb" {
		t.Errorf("dap command = %q", sites[2].Command)
	}
	if sites[0].Env["TOKEN"] != "x" {
		t.Errorf("terminal env not carried: %+v", sites[0].Env)
	}
}

// A shell invoked by absolute path still counts as a shell, which is how a real
// config reaches one: "path": "/bin/sh", "arguments": ["-lc", "…"].
func TestZedSettings_ShellByAbsolutePath(t *testing.T) {
	path := writeZed(t, `{"lsp": {"x": {"binary": {"path": "/bin/sh", "arguments": ["-lc", "exec ruff server"]}}}}`)
	zed, _ := ParseZedSettings(path)
	sites := zed.CommandSites()
	if len(sites) != 1 || sites[0].Command != "/bin/sh -lc exec ruff server" {
		t.Fatalf("expected the shell script to be kept, got %+v", sites)
	}
}

// The three Shell spellings, including the "system" default that names nothing.
func TestZedSettings_ShellSpellings(t *testing.T) {
	for _, c := range []struct{ body, want string }{
		{`"system"`, ""},
		{`{"program": "fish"}`, "fish"},
		{`{"with_arguments": {"program": "nix", "args": ["develop"]}}`, "nix"},
		{`{"with_arguments": {"program": "bash", "args": ["-lc", "echo hi"]}}`, "bash -lc echo hi"},
		{`{}`, ""},
	} {
		path := writeZed(t, `{"terminal": {"shell": `+c.body+`}}`)
		zed, err := ParseZedSettings(path)
		if err != nil {
			t.Fatalf("%s: %v", c.body, err)
		}
		got := ""
		if s := zed.CommandSites(); len(s) > 0 {
			got = s[0].Command
		}
		if got != c.want {
			t.Errorf("%s: command = %q, want %q", c.body, got, c.want)
		}
	}
}

// ignore_system_version defaults to false, so only an explicit true is a waiver.
func TestZedSettings_VersionCheckWaivers(t *testing.T) {
	path := writeZed(t, `{"lsp": {
      "a": {"binary": {"path": "x", "ignore_system_version": true}},
      "b": {"binary": {"path": "y", "ignore_system_version": false}},
      "c": {"binary": {"path": "z"}}}}`)
	zed, _ := ParseZedSettings(path)
	got := zed.VersionCheckWaivers()
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("waivers = %v, want [a]", got)
	}
}

// A settings file with only editor preferences produces no target at all.
func TestZedSettings_NoCommandSites(t *testing.T) {
	path := writeZed(t, `{"theme": "One Dark", "lsp": {"x": {"settings": {"a": 1}}}}`)
	zed, _ := ParseZedSettings(path)
	if zed.HasCommandSites() {
		t.Errorf("expected no command sites, got %+v", zed.CommandSites())
	}
}
