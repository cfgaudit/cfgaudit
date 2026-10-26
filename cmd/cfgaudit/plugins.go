// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/rules"
)

// buildPluginTargets discovers Claude Code plugin/skill packages and turns their
// bundled artifacts into scan targets, reusing the existing rule engine:
//
//   - SKILL.md          → ClaudeMD target (CFG024 hidden Unicode, CFG026 bypass)
//   - hooks.json        → hook command target (CFG008/009/014/015/027/028)
//   - plugin.json       → MCP server target (CFG010/011/017–021), and the
//     plugin's slash commands and agents as instruction targets (#937, #939)
//
// Project-root settings.json / .mcp.json are intentionally left to buildTargets
// so nothing is scanned twice.
func buildPluginTargets(dir, explicit string, includeUser bool) ([]*rules.Target, error) {
	roots, err := pluginRoots(dir, explicit, includeUser)
	if err != nil {
		return nil, err
	}
	var all []*rules.Target
	for _, root := range roots {
		fmt.Fprintf(os.Stderr, "cfgaudit: scanning plugin package %s\n", root)
		var ts []*rules.Target
		if isSkillsDirPlugin(root) {
			// A manifest that does not parse keeps the whole plugin from loading:
			// on 2.1.288 a merge-conflict marker in plugin.json logged "Plugin
			// probe has a corrupt manifest file" and its SessionStart hook did not
			// run. So the manifest is reported and nothing else of the plugin is.
			manifest := filepath.Join(root, claudePluginDir, "plugin.json")
			m, err := parser.ParsePluginManifest(manifest)
			if err != nil {
				all = append(all, unreadablePluginTarget(dir, manifest, err))
				continue
			}
			// Auto-discovered from the repository rather than named on the command
			// line, so any other broken file is reported (CFG109) instead of ending
			// the scan, as for every other committed config (#606).
			ts = skillsDirPluginTargets(root, manifest, m, func(path string, err error) {
				all = append(all, unreadablePluginTarget(dir, path, err))
			})
		} else {
			// A root found in the repository reports a broken file (CFG109) and
			// goes on. A path named with --plugins still stops the scan when one
			// of that plugin's own files is broken (#825), but not for a file
			// deeper in its tree, such as a deliberately malformed test fixture
			// (#848).
			var fatal error
			unreadable := func(path string, err error) {
				if root == explicit && fatal == nil && ownPluginFile(root, path) {
					fatal = err
					return
				}
				all = append(all, unreadablePluginTarget(dir, path, err))
			}
			ts, err = scanPluginRoot(root, unreadable)
			if err == nil {
				err = fatal
			}
		}
		if err != nil {
			return nil, err
		}
		all = append(all, ts...)
	}
	return all, nil
}

// skillsDirPluginTargets builds targets for the components Claude Code loads
// from a skills-directory plugin, not for every file in its tree. Such a folder
// often vendors a whole upstream repository, and the wider walk the --plugins
// scan does would report files that never load: on 2.1.288 a hooks.json one
// directory below the plugin's hooks/ did not run unless the manifest named it.
// What loads:
//
//   - hooks/hooks.json, plus any hook file the manifest names under "hooks"
//   - the MCP servers plugin.json declares, inline or through its path form
//   - every SKILL.md under skills/, plus under any path the manifest names under
//     "skills" (a custom path adds to the default directory)
//   - the slash commands under commands/ and the agents under agents/, or the
//     paths the manifest names under "commands" and "agents", which replace
//     those directories (#937, #939)
//
// A component path that resolves outside the plugin root is skipped.
func skillsDirPluginTargets(root, manifest string, m *parser.PluginManifest, unreadable func(path string, err error)) []*rules.Target {
	var targets []*rules.Target
	hookFiles := []string{filepath.Join(root, "hooks", "hooks.json")}
	for _, rel := range parser.ManifestPaths(m.Hooks) {
		if p, ok := insideRoot(root, rel); ok {
			hookFiles = append(hookFiles, p)
		}
	}
	seen := map[string]bool{}
	for _, p := range hookFiles {
		if seen[p] || !fileExists(p) {
			continue
		}
		seen[p] = true
		t, err := pluginHooksTarget(p)
		if err != nil {
			unreadable(p, err)
			continue
		}
		if t != nil {
			targets = append(targets, t)
		}
	}

	if t, err := pluginMCPTarget(manifest); err != nil {
		unreadable(manifest, err)
	} else if t != nil {
		targets = append(targets, t)
	}

	for _, path := range pluginInstructionFiles(root, m) {
		content, err := scanroot.ReadFile(path)
		if err != nil {
			unreadable(path, err)
			continue
		}
		targets = append(targets, &rules.Target{InstructionFile: path, InstructionContent: string(content)})
	}

	skillDirs := []string{filepath.Join(root, "skills")}
	for _, rel := range parser.ManifestPaths(m.Skills) {
		if p, ok := insideRoot(root, rel); ok {
			skillDirs = append(skillDirs, p)
		}
	}
	for _, d := range skillDirs {
		_ = filepath.WalkDir(d, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() {
				switch e.Name() {
				case ".git", "node_modules", "vendor":
					return fs.SkipDir
				}
				return nil
			}
			if e.Name() != "SKILL.md" || seen[path] {
				return nil
			}
			seen[path] = true
			content, err := scanroot.ReadFile(path)
			if err != nil {
				unreadable(path, err)
				return nil
			}
			targets = append(targets, &rules.Target{InstructionFile: path, InstructionContent: string(content)})
			return nil
		})
	}
	return targets
}

// rootSkillTargets returns a target for each SKILL.md under the scanned
// directory's own skills/ folder that no plugin target already reads. Skill
// collections and plugin repositories keep their skills there, and installers
// copy from it, but without --plugins none of them was scanned (#912). Only the
// skills are read here; a plugin's hooks and MCP servers stay with --plugins,
// which also reads its manifest.
func rootSkillTargets(dir string, have []*rules.Target) []*rules.Target {
	root := filepath.Join(dir, "skills")
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return nil
	}
	seen := map[string]bool{}
	for _, t := range have {
		if t.InstructionFile != "" {
			seen[absPath(t.InstructionFile)] = true
		}
	}
	var targets []*rules.Target
	_ = filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if e.IsDir() {
			switch e.Name() {
			case ".git", "node_modules", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if e.Name() != "SKILL.md" || seen[absPath(path)] {
			return nil
		}
		content, err := scanroot.ReadFile(path)
		if err != nil {
			return nil
		}
		targets = append(targets, &rules.Target{Scope: finding.ScopeProject, InstructionFile: path, InstructionContent: string(content)})
		return nil
	})
	return targets
}

// insideRoot resolves a manifest component path against the plugin root and
// reports whether it stays inside it.
func insideRoot(root, rel string) (string, bool) {
	p := filepath.Join(root, filepath.FromSlash(rel))
	r, err := filepath.Rel(root, p)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", false
	}
	return p, true
}

// isSkillsDirPlugin reports whether root is a plugin folder directly under a
// .claude/skills directory.
func isSkillsDirPlugin(root string) bool {
	parent := filepath.Dir(filepath.Clean(root))
	return filepath.Base(parent) == "skills" && filepath.Base(filepath.Dir(parent)) == ".claude"
}

// unreadablePluginTarget is the CFG109 target for a skills-directory plugin file
// that does not parse, built the same way unreadableTargets builds one.
func unreadablePluginTarget(dir, path string, err error) *rules.Target {
	reason := err.Error()
	if i := strings.Index(reason, ": "); i >= 0 && strings.HasPrefix(reason, "parse ") {
		reason = reason[i+2:]
	}
	scope := finding.ScopeProject
	if !strings.HasPrefix(path, dir) {
		scope = finding.ScopeUser
	}
	return &rules.Target{Scope: scope, UnreadableFile: path, UnreadableReason: reason}
}

// pluginRoots resolves the directories to scan: an explicit --plugins path, the
// scanned project when it bundles a plugin (.claude-plugin/ present), the
// project's skills-directory plugins, and ~/.claude/plugins plus the user's
// skills-directory plugins under --user. Missing directories, duplicates and
// roots inside an already-listed root (whose walk covers them) are skipped.
func pluginRoots(dir, explicit string, includeUser bool) ([]string, error) {
	var roots []string
	var seen []string
	add := func(p string) {
		if p == "" || !dirExists(p) {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		for _, s := range seen {
			if abs == s || strings.HasPrefix(abs, s+string(filepath.Separator)) {
				return
			}
		}
		seen = append(seen, abs)
		roots = append(roots, p)
	}

	add(explicit)
	if dirExists(filepath.Join(dir, claudePluginDir)) {
		add(dir)
	}
	// A Kimi Code plugin marks itself with a kimi.plugin.json at its root
	// (agent-core/src/plugin/manifest.ts `KIMI_PLUGIN_ROOT_PATH`), the same way a
	// Claude plugin marks itself with .claude-plugin/ (#440).
	if fileExists(filepath.Join(dir, kimiPluginManifest)) {
		add(dir)
	}
	// The user's own settings are left out of the project chain on purpose: the
	// scan audits the repository for whoever clones it, and their settings are
	// not in the repository.
	projectSettings := skillsDirSettings(dir)
	for _, p := range skillsDirPlugins(filepath.Join(dir, ".claude", "skills"), projectSettings) {
		add(p)
	}
	if includeUser {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		add(filepath.Join(home, ".claude", "plugins"))
		// The user's settings rank below the project's, so they go first in the
		// chain and the project's later entries win.
		chain := append([]map[string]json.RawMessage{enabledPluginsOf(filepath.Join(home, ".claude", "settings.json"))}, projectSettings...)
		for _, p := range skillsDirPlugins(filepath.Join(home, ".claude", "skills"), chain) {
			add(p)
		}
	}
	return roots, nil
}

// skillsDirPlugins returns the folders directly under skillsDir that Claude Code
// loads as plugins (#609): any `<name>/` holding a .claude-plugin/plugin.json,
// with no install step and no enabledPlugins entry. The plugin documentation
// lists both `~/.claude/skills/` and the project's `.claude/skills/` as
// `@skills-dir` sources, and a repository can share a plugin by placing it
// there. Measured on 2.1.281 through 2.1.288: a SessionStart hook in
// `.claude/skills/<name>/hooks/hooks.json` ran, and a stdio server in its
// plugin.json started. The manifest is the marker: a .claude-plugin/ holding no
// plugin.json (or only a marketplace.json) loaded nothing, and a SKILL.md is not
// needed.
//
// A plugin that does not load is left out. Whether it loads is the manifest's
// defaultEnabled (absent means true), overridden by `"<name>@skills-dir"` in
// enabledPlugins, where the later settings file in chain wins. <name> is the
// manifest's name, not the folder's: on 2.1.288 a setting keyed by the folder
// name changed nothing while one keyed by the manifest name disabled the plugin.
func skillsDirPlugins(skillsDir string, chain []map[string]json.RawMessage) []string {
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		root := filepath.Join(skillsDir, e.Name())
		if !fileExists(filepath.Join(root, claudePluginDir, "plugin.json")) {
			continue
		}
		if !skillsDirPluginEnabled(root, e.Name(), chain) {
			fmt.Fprintf(os.Stderr, "cfgaudit: skipping disabled skills-directory plugin %s\n", root)
			continue
		}
		out = append(out, root)
	}
	return out
}

func skillsDirPluginEnabled(root, folder string, chain []map[string]json.RawMessage) bool {
	name, enabled := folder, true
	// A manifest that does not parse is not a reason to skip the plugin: the scan
	// of its root reports the parse error, and staying enabled keeps it in view.
	if m, err := parser.ParsePluginManifest(filepath.Join(root, claudePluginDir, "plugin.json")); err == nil {
		if m.Name != "" {
			name = m.Name
		}
		if m.DefaultEnabled != nil {
			enabled = *m.DefaultEnabled
		}
	}
	for _, settings := range chain {
		var v bool
		if raw, ok := settings[name+"@skills-dir"]; ok && json.Unmarshal(raw, &v) == nil {
			enabled = v
		}
	}
	return enabled
}

// skillsDirSettings returns the enabledPlugins maps of the project's settings
// files in precedence order, lowest first: settings.json, then
// settings.local.json.
func skillsDirSettings(dir string) []map[string]json.RawMessage {
	return []map[string]json.RawMessage{
		enabledPluginsOf(filepath.Join(dir, ".claude", "settings.json")),
		enabledPluginsOf(filepath.Join(dir, ".claude", "settings.local.json")),
	}
}

// enabledPluginsOf reads a settings file's enabledPlugins map. A missing or
// unreadable file, and one Claude Code discards whole for a top-level type
// mismatch or an unloadable guard hook (#595, #639), contribute nothing: a disable in a file that never loads
// must not hide a plugin that does.
func enabledPluginsOf(path string) map[string]json.RawMessage {
	s, err := parser.ParseSettings(path)
	if err != nil || rules.SettingsDiscarded(s, nil) {
		return nil
	}
	var m map[string]json.RawMessage
	if raw, ok := s.Raw["enabledPlugins"]; ok {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

// dropDuplicateInstructions removes plugin targets that only carry an
// instruction file the project or user scan already reads. A SKILL.md at
// .claude/skills/<name>/ is both a project skill and part of a plugin rooted
// there (or at a repo root that is itself a plugin), and scanning it twice
// reported every content finding twice.
func dropDuplicateInstructions(base, plugin []*rules.Target) []*rules.Target {
	seen := map[string]bool{}
	for _, t := range base {
		if t.InstructionFile != "" {
			seen[absPath(t.InstructionFile)] = true
		}
	}
	out := plugin[:0]
	for _, t := range plugin {
		if t.InstructionFile != "" && t.SettingsFile == "" && t.ProjectMCPFile == "" && seen[absPath(t.InstructionFile)] {
			continue
		}
		out = append(out, t)
	}
	return out
}

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

// scanPluginRoot walks a plugin package tree and builds a target per recognised
// artifact. With unreadable set, a file that does not parse is handed to it and
// the walk goes on; without, the error ends the walk.
func scanPluginRoot(root string, unreadable func(path string, err error)) ([]*rules.Target, error) {
	var targets []*rules.Target
	fail := func(path string, err error) error {
		if unreadable == nil {
			return err
		}
		unreadable(path, err)
		return nil
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		switch d.Name() {
		case "SKILL.md":
			content, err := scanroot.ReadFile(path)
			if err != nil {
				return fail(path, err)
			}
			targets = append(targets, &rules.Target{InstructionFile: path, InstructionContent: string(content)})
		case "hooks.json":
			if !isPluginHooksFile(path) {
				return nil
			}
			t, err := pluginHooksTarget(path)
			if err != nil {
				return fail(path, err)
			}
			if t != nil {
				targets = append(targets, t)
			}
		case "plugin.json":
			t, err := pluginMCPTarget(path)
			if err != nil {
				return fail(path, err)
			}
			if t != nil {
				targets = append(targets, t)
			}
			if filepath.Base(filepath.Dir(path)) == claudePluginDir {
				// pluginMCPTarget parsed the manifest already, so it parses here.
				m, _ := parser.ParsePluginManifest(path)
				for _, f := range pluginInstructionFiles(filepath.Dir(filepath.Dir(path)), m) {
					content, err := scanroot.ReadFile(f)
					if err != nil {
						if err := fail(f, err); err != nil {
							return err
						}
						continue
					}
					targets = append(targets, &rules.Target{InstructionFile: f, InstructionContent: string(content)})
				}
			}
		case "marketplace.json":
			// Only the manifest in .claude-plugin/ is the marketplace document.
			// Matching the bare filename anywhere in the tree would decode an
			// unrelated file as one.
			if filepath.Base(filepath.Dir(path)) != claudePluginDir {
				return nil
			}
			t, err := marketplaceTarget(path)
			if err != nil {
				return fail(path, err)
			}
			if t != nil {
				targets = append(targets, t)
			}
		case kimiPluginManifest:
			ts, err := kimiPluginTargets(path)
			if err != nil {
				return fail(path, err)
			}
			targets = append(targets, ts...)
		}
		return nil
	})
	return targets, err
}

// isPluginHooksFile reports whether a hooks.json found in the plugin walk is in
// the place a Claude Code plugin keeps its hooks, <plugin>/hooks/hooks.json. A
// hooks.json elsewhere, and one in the project's own .claude/hooks/ (Claude
// Code reads project hooks from settings.json, not from there), belongs to
// something else: a marketplace repository with another tool's
// .claude/hooks/hooks.json stopped the whole scan (#825).
func isPluginHooksFile(path string) bool {
	dir := filepath.Dir(path)
	return filepath.Base(dir) == "hooks" && filepath.Base(filepath.Dir(dir)) != ".claude"
}

// ownPluginFile reports whether path is one of the files that make up the
// plugin at root itself: its manifests at the root or in .claude-plugin/, and
// its hooks/hooks.json. Anything deeper belongs to something else in the tree.
func ownPluginFile(root, path string) bool {
	rel, err := filepath.Rel(root, filepath.Dir(path))
	if err != nil {
		return false
	}
	switch filepath.ToSlash(rel) {
	case ".", claudePluginDir, "hooks":
		return true
	}
	return false
}

// kimiPluginManifest is the file a Kimi Code plugin declares itself with, at its
// root.
const kimiPluginManifest = "kimi.plugin.json"

// claudePluginDir is the directory a Claude Code plugin declares itself with, and
// the only place a marketplace.json is the marketplace manifest.
const claudePluginDir = ".claude-plugin"

// marketplaceTarget parses a .claude-plugin/marketplace.json into a target for
// CFG098. Returns nil when the manifest lists no plugins, so an empty or
// placeholder manifest produces no target rather than an empty one.
func marketplaceTarget(path string) (*rules.Target, error) {
	m, err := parser.ParseMarketplace(path)
	if err != nil {
		return nil, err
	}
	if len(m.Plugins) == 0 {
		return nil, nil
	}
	return &rules.Target{MarketplaceFile: path, Marketplace: m}, nil
}

// kimiPluginTargets turns a kimi.plugin.json into targets for the artifacts it
// declares (#440):
//
//   - mcpServers        → the MCP rules, as for a Claude plugin.json
//   - systemPrompt      → instruction content, the CFG092 class: text a committed
//     manifest contributes to the agent's system prompt
//   - systemPromptPath  → the same, read from the file it points at
//
// Bundled skills need nothing here: the walk already turns every SKILL.md in the
// tree into an instruction target.
//
// The manifest's `hooks` array is deliberately not decoded. It is a distinct
// schema (an array of HookDefConfig, not the event → matcher groups map every
// other agent uses), and routing it would need a decoder this issue does not ask
// for.
//
// Scope, stated plainly because it is unusual for this tool: a Kimi plugin is
// loaded from the user's install store, never from a scanned repository, and
// there is no committed key that enables one — plugin enablement lives in that
// store (agent-core-v2/src/app/plugin/manager.ts reads `readInstalled(kimiHomeDir)`),
// which a repo cannot write. So this is author-side coverage: it audits a repo
// that *is* a plugin, for the author publishing it or a reviewer reading it
// before installing. That is exactly what the .claude-plugin/ handling above
// does, which is why it lives here rather than in buildTargets.
func kimiPluginTargets(path string) ([]*rules.Target, error) {
	manifest, err := parser.ParseKimiPluginManifest(path)
	if err != nil {
		return nil, err
	}
	var targets []*rules.Target
	if len(manifest.MCPServers) > 0 {
		targets = append(targets, &rules.Target{ProjectMCPFile: path, ProjectMCP: manifest.MCPServers})
	}
	if prompt := strings.TrimSpace(manifest.SystemPrompt); prompt != "" {
		targets = append(targets, &rules.Target{InstructionFile: path, InstructionContent: manifest.SystemPrompt})
	}
	if rel := strings.TrimSpace(manifest.SystemPromptPath); rel != "" {
		promptPath := filepath.Join(filepath.Dir(path), filepath.FromSlash(rel))
		content, err := scanroot.ReadFile(promptPath)
		switch {
		case err == nil:
			if strings.TrimSpace(string(content)) != "" {
				targets = append(targets, &rules.Target{InstructionFile: promptPath, InstructionContent: string(content)})
			}
		case scanroot.IsAbsent(err):
			// Kimi records a diagnostic and skips a missing file rather than
			// failing the plugin, so a dangling path is not a scan error either.
		default:
			return nil, fmt.Errorf("read %s: %w", promptPath, err)
		}
	}
	return targets, nil
}

// A plugin's slash commands (#937) and agents (#939) are instruction targets: a
// command's body is the prompt Claude Code sends when it runs, and an agent's
// body is its subagent's system prompt, so the content rules read them as they
// read .claude/commands and .claude/agents. Their frontmatter blocks are not
// decoded. On 2.1.310 a Stop hook in a plugin command did not run, while the
// same hook in a plugin skill and in hooks/hooks.json did. For a plugin agent
// the print-mode run was inconclusive, since a project subagent's hooks did not
// run there either; that waits for a trusted-workspace measurement (#939).
//
// pluginComponentFiles lists the .md files Claude Code loads from a plugin
// for a manifest component field: the paths the manifest names (a .md file, or
// a directory walked for them), which replace the default directory, or else
// <defaultDir>/**/*.md. Measured on 2.1.310 for "commands" and for "agents".
// A path that leaves the plugin root is skipped.
func pluginComponentFiles(root string, named json.RawMessage, defaultDir string) []string {
	dirs := []string{filepath.Join(root, defaultDir)}
	var files []string
	if paths := parser.ManifestPaths(named); len(paths) > 0 {
		dirs = nil
		for _, rel := range paths {
			p, ok := insideRoot(root, rel)
			if !ok {
				continue
			}
			switch {
			case dirExists(p):
				dirs = append(dirs, p)
			case fileExists(p) && strings.EqualFold(filepath.Ext(p), ".md"):
				files = append(files, p)
			}
		}
	}
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() {
				switch e.Name() {
				case ".git", "node_modules", "vendor":
					return fs.SkipDir
				}
				return nil
			}
			if strings.EqualFold(filepath.Ext(path), ".md") {
				files = append(files, path)
			}
			return nil
		})
	}
	return files
}

// pluginInstructionFiles is every command and agent file of the plugin at
// root, in that order.
func pluginInstructionFiles(root string, m *parser.PluginManifest) []string {
	var commands, agents json.RawMessage
	if m != nil {
		commands, agents = m.Commands, m.Agents
	}
	return append(pluginComponentFiles(root, commands, "commands"), pluginComponentFiles(root, agents, "agents")...)
}

// pluginHooksTarget parses a plugin hooks.json into a target carrying only its
// hooks (no Raw), so the command-content rules fire but settings-shape rules
// (schema, deny-absent, …) stay inert.
func pluginHooksTarget(path string) (*rules.Target, error) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s parser.Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(s.Hooks) == 0 {
		return nil, nil
	}
	return &rules.Target{SettingsFile: path, Settings: &s}, nil
}

// pluginMCPTarget extracts mcpServers from a plugin.json into a target so the MCP
// rules apply. Returns nil when the manifest declares no servers.
//
// mcpServers has two spellings and both are honoured by Claude Code: an inline
// object, and a string path to an external config resolved against the plugin
// root. The finding is attributed to whichever file really declares the servers,
// so a reader is sent to the file they have to edit (#505).
func pluginMCPTarget(path string) (*rules.Target, error) {
	m, err := parser.ParsePluginManifest(path)
	if err != nil {
		return nil, err
	}
	servers, file, err := m.MCPServerRef(path)
	if err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return nil, nil
	}
	return &rules.Target{ProjectMCPFile: file, ProjectMCP: servers}, nil
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
