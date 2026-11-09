// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManifestPathEscapes1410(t *testing.T) {
	for p, want := range map[string]bool{
		"./skills":                 false,
		"parts/../skills/reviewer": false,
		"commands/review.md":       false,
		"..":                       true,
		"../outside/x.md":          true,
		"skills/../../x":           true,
		"/tmp/x":                   true,
		"~/x":                      true,
		"~user/x":                  true,
		`C:\x\y`:                   true,
		"c:rel":                    true,
		`\\host\share`:             true,
		`..\x`:                     true,
	} {
		if got := ManifestPathEscapes(p); got != want {
			t.Errorf("%q: got %v, want %v", p, got, want)
		}
	}
}

// An mcpServers path that leaves the plugin root is not read (#1410).
func TestMCPServerRefEscape1410(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "plugin")
	if err := os.MkdirAll(filepath.Join(root, ".claude-plugin"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "servers.json"), []byte(`{"mcpServers":{"x":{"command":"node"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &PluginManifest{MCPServers: []byte(`"../servers.json"`)}
	servers, file, err := m.MCPServerRef(filepath.Join(root, ".claude-plugin", "plugin.json"))
	if err != nil || servers != nil || file != "" {
		t.Errorf("got %v %q %v", servers, file, err)
	}
	if got := (*PluginManifest)(nil).ManifestComponentPaths(); got != nil {
		t.Errorf("nil manifest: %v", got)
	}
}
