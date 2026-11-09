// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
	"github.com/cfgaudit/cfgaudit/internal/scanroot"
	"github.com/cfgaudit/cfgaudit/rules"
)

// piTargets reads the parts of a project .pi/ folder of the pi coding agent
// that load code or change commands (#1055), as pi v1.5.0 reads them
// (packages/coding-agent): .pi/settings.json, the extension files in
// .pi/extensions, the "!" commands of .pi/mcp.json and .pi/SYSTEM.md. Its MCP
// servers ride the shared MCP rules through agentMCPFiles, and its instruction
// files ride instructionTargets.
func piTargets(dir string) []*rules.Target {
	t := &rules.Target{Scope: finding.ScopeProject}
	settings := filepath.Join(dir, ".pi", "settings.json")
	if s, err := parser.ParsePiSettings(settings); err == nil {
		t.Pi, t.PiFile = s, settings
	} else if !scanroot.IsAbsent(err) {
		skipUnreadable(settings, err)
	}
	t.PiExtensions = piExtensionFiles(dir)
	// .pi/mcp.json is read here rather than through agentMCPFiles: pi skips a
	// server it cannot read instead of the file, and an env or headers value
	// starting with "!" is a command, not a literal the secret rules judge.
	mcp := filepath.Join(dir, ".pi", "mcp.json")
	if servers, err := parser.ParsePiMCP(mcp); err == nil {
		t.PiMCPCommands, t.PiMCPFile = parser.PiMCPBangCommands(servers), mcp
		if len(servers) > 0 {
			t.ProjectMCP, t.ProjectMCPFile = parser.WithoutPiBangValues(servers), mcp
		}
	} else if !scanroot.IsAbsent(err) {
		skipUnreadable(mcp, err)
	}
	if sys := filepath.Join(dir, ".pi", "SYSTEM.md"); isRegularFile(sys) {
		t.PiSystemFile = sys
	}
	if t.Pi == nil && len(t.PiExtensions) == 0 && t.PiMCPFile == "" && t.PiSystemFile == "" {
		return nil
	}
	return []*rules.Target{t}
}

// piExtensionFiles returns the extensions pi discovers in .pi/extensions:
// *.ts and *.js files, and the index.ts or index.js of a subfolder
// (docs/extensions.md, "Project-local, same layouts").
func piExtensionFiles(dir string) []string {
	root := filepath.Join(dir, ".pi", "extensions")
	entries, err := scanroot.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		p := filepath.Join(root, e.Name())
		if e.IsDir() {
			for _, idx := range []string{"index.ts", "index.js"} {
				if isRegularFile(filepath.Join(p, idx)) {
					out = append(out, filepath.Join(p, idx))
				}
			}
			continue
		}
		if ext := filepath.Ext(e.Name()); (ext == ".ts" || ext == ".js") && !strings.HasSuffix(e.Name(), ".d.ts") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func isRegularFile(path string) bool {
	info, err := scanroot.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
