// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// PluginManifest is the subset of a Claude Code .claude-plugin/plugin.json
// cfgaudit reads. Only the keys that name executable or fetched content are
// modelled.
//
// MCPServers has TWO spellings, which is what this type exists for: an inline
// object, and a STRING path to an external MCP config. Real committed manifests
// use both, and cfgaudit typed it as a map alone, so a string turned the whole
// manifest into a scan error and the servers it pointed at were never audited
// (#505).
//
// Verified against Claude Code 2.1.231 with --plugin-dir. A manifest declaring
// `"mcpServers": "./servers.json"` produced:
//
//	MCP server "plugin:zzrefplugin:zzrefserver": Starting connection
//
// so the reference is followed, the target carries the ordinary
// {"mcpServers": {...}} wrapper, and the resulting server is namespaced
// plugin:<plugin>:<server>. A nested path ("./nested/deep.json") resolves the
// same way, so the base is the plugin root rather than .claude-plugin/.
type PluginManifest struct {
	Name string `json:"name,omitempty"`

	// MCPServers is kept raw because of the two spellings; use MCPServerRef.
	MCPServers json.RawMessage `json:"mcpServers,omitempty"`

	// Skills is decoded only to document that it takes the same string form,
	// pointing at a directory to scan for SKILL.md. It needs no following:
	// cfgaudit walks the whole plugin tree for SKILL.md already, so a redirect
	// inside the plugin is covered wherever it points. Confirmed by the same
	// probe: `"skills": "./mystuff"` logged
	// `Loaded 1 skills from plugin ... custom path: .../mystuff`.
	Skills json.RawMessage `json:"skills,omitempty"`

	// DefaultEnabled decides whether a skills-directory plugin loads when no
	// settings file names it (#609). Absent means enabled. Measured on 2.1.288:
	// `"defaultEnabled": false` kept the plugin's SessionStart hook from running,
	// and `enabledPlugins: {"<name>@skills-dir": true}` in project settings
	// turned it back on.
	DefaultEnabled *bool `json:"defaultEnabled,omitempty"`

	// Hooks names extra hook files to load besides hooks/hooks.json: a string
	// path or an array of them, resolved against the plugin root. Measured on
	// 2.1.288: a hooks.json at sub/hooks/ did not run until the manifest named it
	// with `"hooks": "./sub/hooks/hooks.json"`. An inline object is not decoded.
	Hooks json.RawMessage `json:"hooks,omitempty"`

	// Commands names the plugin's slash-command files or directories: a string
	// path or an array of them, resolved against the plugin root. Unlike skills
	// it replaces the default commands/ directory. Measured on 2.1.310 (#937):
	// with "commands": ["./extra/other.md"], /plug:other loaded and a command in
	// commands/ was "not installed in this session"; without the field the
	// reverse.
	Commands json.RawMessage `json:"commands,omitempty"`

	// Agents names the plugin's agent files or directories, with the same
	// forms as Commands, and replaces the default agents/ directory too.
	// Measured on 2.1.310 (#939): with "agents": ["./extra/owl.md"] the only
	// plugin agent was plug:owl; without the field it was plug:greeter from
	// agents/.
	Agents json.RawMessage `json:"agents,omitempty"`
}

// ManifestPaths decodes a manifest component field that holds a string path or
// an array of them, and drops anything else (an inline object, a non-string
// entry).
func ManifestPaths(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one == "" {
			return nil
		}
		return []string{one}
	}
	var many []json.RawMessage
	if json.Unmarshal(raw, &many) != nil {
		return nil
	}
	var out []string
	for _, m := range many {
		if json.Unmarshal(m, &one) == nil && one != "" {
			out = append(out, one)
		}
	}
	return out
}

// ManifestPathEscapes reports whether a manifest component path leaves the
// plugin root: an absolute path (also a Windows drive or UNC path), one that
// starts with ~, or a relative one that resolves above the root once cleaned
// (#1410). "sub/../skills" stays inside.
func ManifestPathEscapes(rel string) bool {
	p := strings.ReplaceAll(strings.TrimSpace(rel), `\`, "/")
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || filepath.IsAbs(rel) {
		return true
	}
	if len(p) >= 2 && p[1] == ':' && (p[0]|0x20) >= 'a' && (p[0]|0x20) <= 'z' {
		return true // C:/... or C:relative, both off the plugin root
	}
	c := path.Clean(p)
	return c == ".." || strings.HasPrefix(c, "../")
}

// ManifestComponentPaths returns every path-valued component entry of the
// manifest by field, in a fixed field order: skills, agents, commands, hooks,
// and the string form of mcpServers.
func (m *PluginManifest) ManifestComponentPaths() []ManifestComponentPath {
	if m == nil {
		return nil
	}
	var out []ManifestComponentPath
	for _, f := range []struct {
		name string
		raw  json.RawMessage
	}{{"skills", m.Skills}, {"agents", m.Agents}, {"commands", m.Commands}, {"hooks", m.Hooks}, {"mcpServers", m.MCPServers}} {
		for _, p := range ManifestPaths(f.raw) {
			out = append(out, ManifestComponentPath{Field: f.name, Path: p})
		}
	}
	return out
}

// ManifestComponentPath is one path a manifest component field names.
type ManifestComponentPath struct {
	Field, Path string
}

// MCPServerRef returns the manifest's MCP servers. Inline entries come back
// directly; a string path comes back as the file it names, resolved against the
// plugin root, so callers get servers either way and can attribute findings to
// the file they were really declared in.
//
// Returns a nil map and no error when the manifest declares none, or when the
// referenced file is missing: a dangling reference is the plugin author's
// problem to notice at install time, not a scan error.
func (m *PluginManifest) MCPServerRef(manifestPath string) (servers map[string]MCPServer, file string, err error) {
	if m == nil || len(m.MCPServers) == 0 {
		return nil, "", nil
	}
	var inline map[string]MCPServer
	if err := json.Unmarshal(m.MCPServers, &inline); err == nil {
		return inline, manifestPath, nil
	}
	var ref string
	if err := json.Unmarshal(m.MCPServers, &ref); err != nil {
		return nil, "", nil // a shape this version does not model
	}
	ref = strings.TrimSpace(ref)
	if ref == "" || ManifestPathEscapes(ref) {
		return nil, "", nil // CFG135 reports a path that leaves the plugin root
	}
	target := filepath.Join(PluginRootOf(manifestPath), filepath.FromSlash(ref))
	cfg, err := ParseMCPConfig(target)
	if err != nil {
		// errors.Is rather than os.IsNotExist: ParseMCPConfig wraps the read
		// error, and os.IsNotExist does not unwrap, so a dangling reference
		// surfaced as a scan error instead of being skipped.
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", nil
		}
		return nil, "", err
	}
	return cfg.MCPServers, target, nil
}

// PluginDefaultMCP returns the servers of the .mcp.json next to a plugin's
// .claude-plugin directory, and that file. Claude Code loads it without a
// manifest entry, and on 2.1.319 a file with servers replaces the manifest's
// mcpServers, inline or by path. A file it cannot use yields nothing, and then
// the manifest counts: one that does not parse, with a leading BOM, or without
// a server (#1496). The servers can also sit at the top level of the file.
func PluginDefaultMCP(manifestPath string) (map[string]MCPServer, string) {
	if filepath.Base(filepath.Dir(manifestPath)) != ".claude-plugin" {
		return nil, ""
	}
	path := filepath.Join(PluginRootOf(manifestPath), ".mcp.json")
	if cfg, err := ParseMCPConfig(path); err == nil && len(cfg.MCPServers) > 0 {
		return cfg.MCPServers, path
	}
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, ""
	}
	var flat map[string]MCPServer
	if json.Unmarshal(data, &flat) != nil || len(flat) == 0 {
		return nil, ""
	}
	for _, server := range flat {
		if server.Command == "" && server.URL == "" {
			return nil, ""
		}
	}
	return flat, path
}

// PluginRootOf returns the directory a plugin's relative paths resolve against.
// A manifest at <root>/.claude-plugin/plugin.json resolves against <root>;
// anywhere else it resolves against its own directory.
func PluginRootOf(manifestPath string) string {
	dir := filepath.Dir(manifestPath)
	if filepath.Base(dir) == ".claude-plugin" {
		return filepath.Dir(dir)
	}
	return dir
}

// ParsePluginManifest reads and decodes a plugin.json.
func ParsePluginManifest(path string) (*PluginManifest, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m PluginManifest
	if err := json.Unmarshal(stripJSONC(data), &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &m, nil
}
