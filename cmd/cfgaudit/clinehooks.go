// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// clineHookEvents maps a hook file's lower-case base name to its event, from
// HookConfigFileName in sdk/packages/core/src/hooks/hook-file-config.ts.
var clineHookEvents = func() map[string]string {
	events := map[string]string{}
	for _, e := range []string{
		"TaskStart", "TaskResume", "TaskCancel", "TaskComplete", "TaskError",
		"PreToolUse", "PostToolUse", "UserPromptSubmit", "PreCompact", "SessionShutdown",
	} {
		events[strings.ToLower(e)] = e
	}
	return events
}()

// clineHookExts are SUPPORTED_HOOK_FILE_EXTENSIONS in the same file.
var clineHookExts = map[string]bool{
	"": true, ".sh": true, ".bash": true, ".zsh": true, ".js": true, ".mjs": true, ".cjs": true,
	".ts": true, ".mts": true, ".cts": true, ".py": true, ".ps1": true,
}

// clineHookTarget returns a target naming the hook files of a project (#1523),
// or nil when there are none. Cline's hooks are script files named after their
// event, not commands in a config file: listHookConfigFiles reads them from
// .clinerules/hooks and .cline/hooks, without going into subdirectories.
func clineHookTarget(dir string) *rules.Target {
	var hooks []rules.ClineHook
	for _, d := range []string{".clinerules", ".cline"} {
		entries, err := scanroot.ReadDir(filepath.Join(dir, d, "hooks"))
		if err != nil {
			continue
		}
		for _, e := range entries {
			ext := strings.ToLower(filepath.Ext(e.Name()))
			event, ok := clineHookEvents[strings.ToLower(strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())))]
			if ok && clineHookExts[ext] && e.Type().IsRegular() {
				hooks = append(hooks, rules.ClineHook{Path: d + "/hooks/" + e.Name(), Event: event})
			}
		}
	}
	if len(hooks) == 0 {
		return nil
	}
	sort.Slice(hooks, func(i, j int) bool { return hooks[i].Path < hooks[j].Path })
	return &rules.Target{Scope: finding.ScopeProject, ClineHooks: hooks}
}

// foreignShebangRe is a first line naming an interpreter other than a shell.
var foreignShebangRe = regexp.MustCompile(`^#!.*\b(?:node|deno|bun|python[0-9.]*|ruby|perl|php|pwsh)\b`)

// shellHook reports whether a hook file with no extension is a shell script:
// Cline runs it through its shebang, so the first line decides.
func shellHook(rel, content string) bool {
	if filepath.Ext(rel) != "" {
		return false
	}
	first, _, _ := strings.Cut(content, "\n")
	return !foreignShebangRe.MatchString(first)
}
