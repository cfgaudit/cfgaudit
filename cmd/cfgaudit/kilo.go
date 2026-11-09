// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// Kilo Code (#1056) is an OpenCode fork: its CLI and VS Code extension share
// the packages/opencode backend and read OpenCode's config format under Kilo's
// own names. Read from the v7.8.27 source (packages/opencode/src).

// kiloDirs are the config folders Kilo reads where OpenCode reads .opencode,
// .kilocode first and .kilo winning (config/paths.ts, "kilocode_change").
var kiloDirs = []string{".kilocode", ".kilo"}

// kiloConfigFiles are Kilo's own project config files in merge order, lowest
// precedence first: kilo.json and kilo.jsonc at the root ("also discover
// kilo.json project files", config/config.ts), then ALL_CONFIG_FILES in each
// of kiloDirs (kilocode/config/config.ts). The root opencode.json(c), which
// Kilo reads as well, is OpenCode's file and read as such.
func kiloConfigFiles() []string {
	out := []string{"kilo.json", "kilo.jsonc"}
	for _, d := range kiloDirs {
		for _, name := range []string{"kilo.jsonc", "kilo.json", "opencode.jsonc", "opencode.json"} {
			out = append(out, filepath.Join(d, name))
		}
	}
	return out
}

// kiloTargets returns the targets of a project's Kilo files: the configs
// through the OpenCode rules, the legacy mcp.json files through the shared MCP
// rules, and the plugin and tool files through CFG114.
func kiloTargets(dir string) []*rules.Target {
	targets := openCodeFileTargets(dir, kiloConfigFiles())
	for _, d := range kiloDirs {
		// The legacy mcp.json (mcp-migrator.ts) has the mcpServers shape.
		// alwaysAllow "cannot be migrated" and is only warned about, so it is
		// not read: CFG011 would report an approval Kilo does not grant.
		path := filepath.Join(dir, d, "mcp.json")
		// loadMCPConfigOptional reports a broken file through CFG109 and
		// never returns an error.
		servers, _ := loadMCPConfigOptional(path)
		if len(servers) > 0 {
			for name, s := range servers {
				s.AlwaysAllow = nil
				servers[name] = s
			}
			targets = append(targets, &rules.Target{Scope: finding.ScopeProject, ProjectMCP: servers, ProjectMCPFile: path})
		}
		// Plugins ({plugin,plugins}/*.{ts,js}, config/plugin.ts) and tools
		// ({tool,tools}/*.{js,ts}, tool/registry.ts), as in .opencode.
		for _, cd := range []struct{ sub, kind string }{{"plugin", "kilo-plugin"}, {"plugins", "kilo-plugin"}, {"tool", "kilo-tool"}, {"tools", "kilo-tool"}} {
			for _, ext := range []string{"*.ts", "*.js"} {
				matches, _ := scanroot.Glob(filepath.Join(dir, d, cd.sub, ext))
				for _, m := range matches {
					if isRegularFile(m) {
						targets = append(targets, &rules.Target{Scope: finding.ScopeProject, AgentCode: agentCodeFile(m, cd.kind)})
					}
				}
			}
		}
	}
	return targets
}

// kiloInstructionFiles returns the Kilo files whose text reaches the model:
//
//   - in each of kiloDirs: rules/*.md and rules-<mode>/*.md (rules-migrator.ts
//     reads the top level only), workflows/*.md (workflows-migrator.ts), the
//     OpenCode agent, mode and command globs ({agent,agents}/**/*.md,
//     {mode,modes}/*.md, {command,commands}/**/*.md) and
//     {skill,skills}/**/SKILL.md (skill/index.ts);
//   - at the root: .kilocoderules, .kilocoderules-<mode> and .kilocodemodes,
//     whose roleDefinition and customInstructions become the mode's prompt
//     (modes-migrator.ts). Like .roomodes, the whole file is read, so its
//     lines keep their numbers.
func kiloInstructionFiles(dir string) []string {
	var out []string
	glob := func(pattern string) {
		matches, _ := scanroot.Glob(filepath.Join(dir, pattern))
		for _, m := range matches {
			if isRegularFile(m) {
				out = append(out, m)
			}
		}
	}
	walk := func(root string, match func(string) bool) {
		_ = scanroot.WalkDir(filepath.Join(dir, root), func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && match(d.Name()) {
				out = append(out, p)
			}
			return nil
		})
	}
	for _, d := range kiloDirs {
		glob(filepath.Join(d, "rules", "*.md"))
		glob(filepath.Join(d, "rules-*", "*.md"))
		glob(filepath.Join(d, "workflows", "*.md"))
		glob(filepath.Join(d, "mode", "*.md"))
		glob(filepath.Join(d, "modes", "*.md"))
		for _, sub := range []string{"agent", "agents", "command", "commands"} {
			walk(filepath.Join(d, sub), func(name string) bool { return filepath.Ext(name) == ".md" })
		}
		for _, sub := range []string{"skill", "skills"} {
			walk(filepath.Join(d, sub), isSkillFile)
		}
	}
	glob(".kilocoderules")
	glob(".kilocoderules-*")
	glob(".kilocodemodes")
	sort.Strings(out)
	return out
}
