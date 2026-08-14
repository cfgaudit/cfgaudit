package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writePlugin(t *testing.T, manifest string, extra map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude-plugin"), 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".claude-plugin", "plugin.json")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	for rel, body := range extra {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// The inline shape, unchanged.
func TestPluginManifest_InlineServers(t *testing.T) {
	path := writePlugin(t, `{"name":"p","mcpServers":{"a":{"command":"node"}}}`, nil)
	m, err := ParsePluginManifest(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	servers, file, err := m.MCPServerRef(path)
	if err != nil || len(servers) != 1 || servers["a"].Command != "node" {
		t.Fatalf("inline servers: %v %v", servers, err)
	}
	if file != path {
		t.Errorf("inline servers are declared in the manifest, got %q", file)
	}
}

// The string shape, which used to fail the whole parse. Verified against Claude
// Code 2.1.231: the reference is followed and the servers start.
func TestPluginManifest_StringReference(t *testing.T) {
	path := writePlugin(t, `{"name":"p","mcpServers":"./servers.json"}`,
		map[string]string{"servers.json": `{"mcpServers":{"ref":{"command":"node"}}}`})
	m, err := ParsePluginManifest(path)
	if err != nil {
		t.Fatalf("a string reference must not fail the parse: %v", err)
	}
	servers, file, err := m.MCPServerRef(path)
	if err != nil {
		t.Fatalf("MCPServerRef: %v", err)
	}
	if len(servers) != 1 || servers["ref"].Command != "node" {
		t.Fatalf("expected the referenced server, got %v", servers)
	}
	// Attributed to the file that really declares them.
	if want := filepath.Join(filepath.Dir(filepath.Dir(path)), "servers.json"); file != want {
		t.Errorf("file = %q, want %q", file, want)
	}
}

// A nested path resolves against the plugin root, not .claude-plugin/.
func TestPluginManifest_NestedReference(t *testing.T) {
	path := writePlugin(t, `{"name":"p","mcpServers":"./nested/deep.json"}`,
		map[string]string{"nested/deep.json": `{"mcpServers":{"d":{"command":"node"}}}`})
	m, _ := ParsePluginManifest(path)
	servers, _, err := m.MCPServerRef(path)
	if err != nil || len(servers) != 1 {
		t.Fatalf("nested reference: %v %v", servers, err)
	}
	// The other real spelling in the wild points back into .claude-plugin/.
	path2 := writePlugin(t, `{"name":"p","mcpServers":"./.claude-plugin/mcp.json"}`,
		map[string]string{".claude-plugin/mcp.json": `{"mcpServers":{"c":{"command":"node"}}}`})
	m2, _ := ParsePluginManifest(path2)
	servers2, _, err := m2.MCPServerRef(path2)
	if err != nil || len(servers2) != 1 {
		t.Fatalf("in-directory reference: %v %v", servers2, err)
	}
}

// A dangling reference is the author's problem to notice at install time, not a
// scan error. os.IsNotExist does not unwrap, which is why errors.Is is used.
func TestPluginManifest_DanglingReference(t *testing.T) {
	path := writePlugin(t, `{"name":"p","mcpServers":"./gone.json"}`, nil)
	m, _ := ParsePluginManifest(path)
	servers, file, err := m.MCPServerRef(path)
	if err != nil {
		t.Errorf("a dangling reference must not be a scan error, got %v", err)
	}
	if servers != nil || file != "" {
		t.Errorf("expected nothing, got %v %q", servers, file)
	}
}

func TestPluginManifest_AbsentAndUnmodelledShapes(t *testing.T) {
	for _, manifest := range []string{
		`{"name":"p"}`,
		`{"name":"p","mcpServers":""}`,
		`{"name":"p","mcpServers":123}`,
		`{"name":"p","skills":"./skills/"}`,
	} {
		path := writePlugin(t, manifest, nil)
		m, err := ParsePluginManifest(path)
		if err != nil {
			t.Errorf("%s must not fail the parse: %v", manifest, err)
			continue
		}
		if servers, _, err := m.MCPServerRef(path); err != nil || servers != nil {
			t.Errorf("%s: expected no servers, got %v %v", manifest, servers, err)
		}
	}
}

func TestPluginRootOf(t *testing.T) {
	in := filepath.Join("x", "plug", ".claude-plugin", "plugin.json")
	if got, want := PluginRootOf(in), filepath.Join("x", "plug"); got != want {
		t.Errorf("got %q want %q", got, want)
	}
	loose := filepath.Join("x", "plug", "plugin.json")
	if got, want := PluginRootOf(loose), filepath.Join("x", "plug"); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
