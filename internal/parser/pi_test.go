// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// #1055: pi package sources and their pinning.
func TestPiPackageSources(t *testing.T) {
	s := &PiSettings{Packages: []byte(`["npm:@x/a", "npm:@x/b@1.2.3", "npm:c@^1", "npm:d@v2.0.0-rc.1", "git:github.com/x/y", "git:github.com/x/z@v1",
		"https://github.com/x/u", "https://github.com/x/w@abc123", "git@github.com:x/q@v2", "./local", {"source": "npm:e@1.0.0"}, {"source": ""}, 3, ""]`)}
	got := s.PackageSources()
	want := []PiPackage{
		{"npm:@x/a", "npm", false}, {"npm:@x/b@1.2.3", "npm", true}, {"npm:c@^1", "npm", false}, {"npm:d@v2.0.0-rc.1", "npm", true},
		{"git:github.com/x/y", "git", false}, {"git:github.com/x/z@v1", "git", true},
		{"https://github.com/x/u", "git", false}, {"https://github.com/x/w@abc123", "git", true}, {"git@github.com:x/q@v2", "git", true},
		{"./local", "local", false}, {"npm:e@1.0.0", "npm", true},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
	if (&PiSettings{Packages: []byte(`{"a":1}`)}).PackageSources() != nil || (*PiSettings)(nil).PackageSources() != nil {
		t.Error("wrong shape")
	}
}

func TestParsePiSettings(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(p, []byte("\ufeff{\"shellPath\": \"/bin/zsh\", \"npmCommand\": [\"pnpm\", 1, \" \"]}"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ParsePiSettings(p)
	if err != nil || PiString(s.ShellPath) != "/bin/zsh" || !slices.Equal(PiStrings(s.NpmCommand), []string{"pnpm"}) {
		t.Fatalf("%+v %v", s, err)
	}
	if PiString([]byte(`1`)) != "" || PiStrings([]byte(`"x"`)) != nil {
		t.Error("wrong types")
	}
	if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePiSettings(p); err == nil {
		t.Error("broken file parsed")
	}
	if _, err := ParsePiSettings(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file parsed")
	}
}

func TestPiMCPBangCommands(t *testing.T) {
	servers := map[string]MCPServer{
		"b": {Env: EnvMap{"T": "!curl x", "U": "${U}", "V": " !no", "W": "!"}},
		"a": {Headers: map[string]string{"Authorization": "!echo Bearer $(gh auth token)"}},
	}
	got := PiMCPBangCommands(servers)
	want := []PiBangCommand{{"a", "headers", "Authorization", "echo Bearer $(gh auth token)"}, {"b", "env", "T", "curl x"}}
	if !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
	clean := WithoutPiBangValues(servers)
	if _, ok := clean["b"].Env["T"]; ok || clean["b"].Env["U"] != "${U}" || len(clean["a"].Headers) != 0 || clean["c"].Env != nil {
		t.Errorf("clean %v", clean)
	}
}

// pi skips a server it cannot read, not the file.
func TestParsePiMCP(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(p, []byte(`{"mcpServers": {"bad": {"url": "https://x.example", "auth": false}, "ok": {"command": "node", "env": {"T": "!gh auth token"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	servers, err := ParsePiMCP(p)
	if err != nil || len(servers) != 1 || servers["ok"].Command != "node" || servers["ok"].Env["T"] != "!gh auth token" {
		t.Fatalf("%v %v", servers, err)
	}
	if err := os.WriteFile(p, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePiMCP(p); err == nil {
		t.Error("broken file parsed")
	}
	if _, err := ParsePiMCP(filepath.Join(dir, "none.json")); err == nil {
		t.Error("missing file parsed")
	}
}

// pi v1.5.0 rejects a non-object auth only on an HTTP server (#1666); a stdio
// server, an HTTP server with an auth object and a server of another type
// are kept.
func TestParsePiMCPAuth1666(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mcp.json")
	doc := `{"mcpServers": {
		"http-string": {"url": "https://a.example", "auth": "oauth"},
		"http-null": {"url": "https://b.example", "auth": null},
		"http-typed": {"type": "streamable-http", "url": "https://c.example", "auth": ["x"]},
		"http-object": {"url": "https://d.example", "auth": {"provider": "github"}},
		"stdio-string": {"command": "node", "auth": "oauth"},
		"stdio-typed": {"type": "stdio", "command": "node", "url": "https://e.example", "auth": true}
	}}`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	servers, err := ParsePiMCP(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"http-string", "http-null", "http-typed"} {
		if _, ok := servers[name]; ok {
			t.Errorf("%s kept, pi rejects it", name)
		}
	}
	for _, name := range []string{"http-object", "stdio-string", "stdio-typed"} {
		if _, ok := servers[name]; !ok {
			t.Errorf("%s dropped, pi loads it", name)
		}
	}
}
