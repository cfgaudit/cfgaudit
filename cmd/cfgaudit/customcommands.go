// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// customCommandDirs are the custom command folders of Gemini CLI and Qwen
// Code (#750), each walked for `**/*.toml` (FileCommandLoader.ts, Gemini
// v0.67.0, Qwen v0.27.0). Qwen also loads `**/*.md` from its folder.
var customCommandDirs = []string{
	filepath.Join(".gemini", "commands"),
	filepath.Join(".qwen", "commands"),
}

// customCommandFiles returns the custom command files under base: every .toml
// in either folder and every .md in .qwen/commands, at any depth.
func customCommandFiles(base string) []string {
	var out []string
	for _, rel := range customCommandDirs {
		qwen := strings.HasPrefix(rel, ".qwen")
		_ = scanroot.WalkDir(filepath.Join(base, rel), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			// The loaders' globs match the extension case-sensitively.
			if ext := filepath.Ext(path); ext == ".toml" || (qwen && ext == ".md") {
				out = append(out, path)
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

// customCommandAgent returns "gemini" or "qwen" when path is a custom command
// file in one of customCommandDirs, and "" otherwise.
func customCommandAgent(path string) string {
	slash := "/" + filepath.ToSlash(path)
	switch {
	case strings.Contains(slash, "/.gemini/commands/"):
		return "gemini"
	case strings.Contains(slash, "/.qwen/commands/"):
		return "qwen"
	}
	return ""
}

// customCommandTarget builds the instruction target of a TOML custom command:
// the `prompt` string, placed on its line in the file, with its `!{...}`
// commands. ok is false when the agent skips the file, or when it cannot be
// read: scanroot records an unreadable file or a link out of the repository
// (CFG109, CFG115) and reports it as absent.
func customCommandTarget(path, agent string) (*rules.Target, bool) {
	data, err := scanroot.ReadFile(path)
	if err != nil {
		return nil, false
	}
	cmd, ok := parser.ParseCustomCommandTOML(data, agent == "qwen")
	if !ok || strings.TrimSpace(cmd.Prompt) == "" {
		return nil, false
	}
	return &rules.Target{
		InstructionFile:    path,
		InstructionContent: strings.Repeat("\n", max(cmd.Line-1, 0)) + cmd.Prompt,
		SkillShellCommands: parser.CustomCommandShellCommands(cmd.Prompt),
	}, true
}
