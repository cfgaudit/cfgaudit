package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/rules"
)

// buildPluginTargets discovers Claude Code plugin/skill packages and turns their
// bundled artifacts into scan targets, reusing the existing rule engine:
//
//   - SKILL.md          → ClaudeMD target (CFG024 hidden Unicode, CFG026 bypass)
//   - hooks.json        → hook command target (CFG008/009/014/015/027/028)
//   - plugin.json       → MCP server target (CFG010/011/017–021)
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
		ts, err := scanPluginRoot(root)
		if err != nil {
			return nil, err
		}
		all = append(all, ts...)
	}
	return all, nil
}

// pluginRoots resolves the directories to scan: an explicit --plugins path, the
// scanned project when it bundles a plugin (.claude-plugin/ present), and
// ~/.claude/plugins under --user. Missing directories and duplicates are skipped.
func pluginRoots(dir, explicit string, includeUser bool) ([]string, error) {
	var roots []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || !dirExists(p) {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		if !seen[abs] {
			seen[abs] = true
			roots = append(roots, p)
		}
	}

	add(explicit)
	if dirExists(filepath.Join(dir, ".claude-plugin")) {
		add(dir)
	}
	if includeUser {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		add(filepath.Join(home, ".claude", "plugins"))
	}
	return roots, nil
}

// scanPluginRoot walks a plugin package tree and builds a target per recognised
// artifact.
func scanPluginRoot(root string) ([]*rules.Target, error) {
	var targets []*rules.Target
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
			content, err := os.ReadFile(path) // #nosec G304,G122 -- local audit tool reading a user-supplied plugin tree; symlink TOCTOU is not in scope
			if err != nil {
				return err
			}
			targets = append(targets, &rules.Target{ClaudeMDFile: path, ClaudeMDContent: string(content)})
		case "hooks.json":
			t, err := pluginHooksTarget(path)
			if err != nil {
				return err
			}
			if t != nil {
				targets = append(targets, t)
			}
		case "plugin.json":
			t, err := pluginMCPTarget(path)
			if err != nil {
				return err
			}
			if t != nil {
				targets = append(targets, t)
			}
		}
		return nil
	})
	return targets, err
}

// pluginHooksTarget parses a plugin hooks.json into a target carrying only its
// hooks (no Raw), so the command-content rules fire but settings-shape rules
// (schema, deny-absent, …) stay inert.
func pluginHooksTarget(path string) (*rules.Target, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from the user-supplied plugin dir
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
func pluginMCPTarget(path string) (*rules.Target, error) {
	cfg, err := parser.ParseMCPConfig(path)
	if err != nil {
		return nil, err
	}
	if len(cfg.MCPServers) == 0 {
		return nil, nil
	}
	return &rules.Target{ProjectMCPFile: path, ProjectMCP: cfg.MCPServers}, nil
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}
