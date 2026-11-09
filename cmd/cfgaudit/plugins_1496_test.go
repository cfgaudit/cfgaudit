// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

// mcpFindings scans dir with the extra args and returns the file and message of
// each CFG010 finding.
func mcpFindings(t *testing.T, dir string, args ...string) []string {
	t.Helper()
	setHome(t, t.TempDir())
	var out, errb bytes.Buffer
	cmd := append([]string{"cfgaudit", "--format", "json", "--only", "CFG010"}, args...)
	if code := run(append(cmd, dir), nil, &out, &errb); code != 0 && code != 1 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var found []struct{ File string }
	if err := json.Unmarshal(out.Bytes(), &found); err != nil {
		t.Fatalf("%v:\n%s", err, out.String())
	}
	files := make([]string, 0, len(found))
	for _, f := range found {
		rel, err := filepath.Rel(dir, f.File)
		if err != nil {
			rel = f.File
		}
		files = append(files, filepath.ToSlash(rel))
	}
	return files
}

const (
	pluginServer = `{"mcpServers":{"s":{"command":"npx","args":["-y","example-mcp"]}}}`
	otherServer  = `{"mcpServers":{"o":{"command":"npx","args":["-y","other-mcp"]}}}`
)

// A plugin's root .mcp.json counts without a manifest entry, and with servers
// it replaces the manifest; a file Claude Code cannot use leaves the manifest
// in force. Measured on 2.1.319 (#1496).
func TestPluginDefaultMCP1496(t *testing.T) {
	inline := `{"name":"p","version":"1.0.0","mcpServers":{"i":{"command":"npx","args":["-y","inline-mcp"]}}}`
	byPath := `{"name":"p","version":"1.0.0","mcpServers":"./other.json"}`
	plain := `{"name":"p","version":"1.0.0"}`
	for name, c := range map[string]struct {
		manifest, mcp string
		want          []string
	}{
		"no manifest entry":  {plain, pluginServer, []string{"plugin/.mcp.json"}},
		"replaces inline":    {inline, pluginServer, []string{"plugin/.mcp.json"}},
		"replaces a path":    {byPath, pluginServer, []string{"plugin/.mcp.json"}},
		"bom leaves inline":  {inline, "\uFEFF" + pluginServer, []string{"plugin/.claude-plugin/plugin.json"}},
		"broken, no servers": {plain, `{"mcpServers":{`, nil},
		"empty leaves path":  {byPath, `{}`, []string{"plugin/other.json"}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			mustWrite(t, filepath.Join(dir, "plugin", ".claude-plugin", "plugin.json"), c.manifest)
			mustWrite(t, filepath.Join(dir, "plugin", ".mcp.json"), c.mcp)
			mustWrite(t, filepath.Join(dir, "plugin", "other.json"), otherServer)
			got := mcpFindings(t, dir, "--plugins", filepath.Join(dir, "plugin"))
			if len(got) != len(c.want) {
				t.Fatalf("findings in %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("finding in %s, want %s", got[i], c.want[i])
				}
			}
		})
	}
}

// A repository that is a plugin has one .mcp.json, whichever way the plugin
// reaches it, so each server is reported once (#1378).
func TestPluginMCPNotReportedTwice1378(t *testing.T) {
	for name, manifest := range map[string]string{
		"default file":  `{"name":"p","version":"1.0.0"}`,
		"manifest path": `{"name":"p","version":"1.0.0","mcpServers":"./.mcp.json"}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			mustWrite(t, filepath.Join(dir, ".claude-plugin", "plugin.json"), manifest)
			mustWrite(t, filepath.Join(dir, ".mcp.json"), pluginServer)
			if got := mcpFindings(t, dir); len(got) != 1 || got[0] != ".mcp.json" {
				t.Errorf("findings in %v, want one in .mcp.json", got)
			}
		})
	}
}
