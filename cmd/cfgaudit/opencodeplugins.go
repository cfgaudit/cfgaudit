// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// openCodeModuleExts are the extensions Bun.resolveSync tries for an
// extensionless specifier, which Host.resolve hands it.
var openCodeModuleExts = []string{".tsx", ".jsx", ".ts", ".mjs", ".js", ".cjs"}

// openCodePluginEntry resolves an OpenCode 2 plugin directory the way
// Host.resolve does (packages/plugin/src/host.ts, v2.2.6) and returns the file
// to report and whether only a desktop (GUI) part loads. A package.json with a
// name and exports resolves through them; without them the server part is
// server or index at the root, and the GUI part gui-experimental.cjs or .js.
// The server part wins (entrypoints.server ?? entrypoints.gui). ok is false for
// a directory with neither, which OpenCode skips.
func openCodePluginEntry(dir string) (path string, gui bool, ok bool) {
	if data, err := scanroot.ReadFile(filepath.Join(dir, "package.json")); err == nil {
		var m struct {
			Name    json.RawMessage `json:"name"`
			Exports json.RawMessage `json:"exports"`
		}
		var name string
		if json.Unmarshal(data, &m) == nil && json.Unmarshal(m.Name, &name) == nil && len(m.Exports) > 0 {
			// The exports map decides the entry; cfgaudit reports the manifest
			// that names it rather than resolving the map.
			return filepath.Join(dir, "package.json"), false, true
		}
	}
	for _, base := range []string{"server", "index", filepath.Join("server", "index")} {
		for _, ext := range openCodeModuleExts {
			p := filepath.Join(dir, base+ext)
			if info, err := scanroot.Stat(p); err == nil && info.Mode().IsRegular() {
				return p, false, true
			}
		}
	}
	for _, name := range []string{"gui-experimental.cjs", "gui-experimental.js"} {
		p := filepath.Join(dir, name)
		if info, err := scanroot.Stat(p); err == nil && info.Mode().IsRegular() {
			return p, true, true
		}
	}
	return "", false, false
}

// openCodePluginDirs returns the plugin directories OpenCode 2 loads from the
// repository (#748): each folder directly in .opencode/{plugin,plugins}
// (PluginSourceDirectory.discover), and each ./ or ../ entry of a config file's
// plugin or plugins key, resolved against that file's folder, that stays in the
// repository and is a folder (a file there is dropped with a warning). A
// symlinked folder is not followed.
func openCodePluginDirs(dir string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, sub := range []string{"plugin", "plugins"} {
		root := filepath.Join(dir, ".opencode", sub)
		entries, err := scanroot.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				add(filepath.Join(root, e.Name()))
			}
		}
	}
	for _, rel := range openCodeConfigFiles {
		path := filepath.Join(dir, rel)
		cfg, err := parser.ParseOpenCodeConfig(path)
		if err != nil {
			continue
		}
		for _, src := range cfg.PluginSources() {
			if !strings.HasPrefix(src, "./") && !strings.HasPrefix(src, "../") {
				continue
			}
			p := filepath.Join(filepath.Dir(path), filepath.FromSlash(src))
			r, err := filepath.Rel(dir, p)
			if err != nil || !filepath.IsLocal(r) {
				continue
			}
			if info, err := scanroot.Stat(p); err == nil && info.IsDir() {
				add(p)
			}
		}
	}
	return out
}

// openCodePluginDirTargets gives CFG114 one target per OpenCode 2 plugin
// directory that has an entry.
func openCodePluginDirTargets(dir string) []*rules.Target {
	var targets []*rules.Target
	for _, d := range openCodePluginDirs(dir) {
		entry, gui, ok := openCodePluginEntry(d)
		if !ok {
			continue
		}
		kind := "plugin-dir"
		if gui {
			kind = "plugin-gui"
		}
		targets = append(targets, &rules.Target{Scope: finding.ScopeProject, AgentCode: agentCodeFile(entry, kind)})
	}
	return targets
}
