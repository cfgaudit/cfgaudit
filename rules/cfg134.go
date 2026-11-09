// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg134 struct{}

// CFG134 reports a project .pi/ folder of the pi coding agent that loads code
// or changes the commands pi runs (#1055).
var CFG134 = &cfg134{}

func init() { All = append(All, CFG134) }

func (r *cfg134) ID() string { return "CFG134" }

// piTrusted is the condition every finding shares: pi asks once whether to
// trust a project with these resources (trust-manager.ts), and after that
// loads them with no further question, also in CI with --approve.
const piTrusted = " once the project is trusted (one prompt, or --approve in print and RPC modes, covers all of .pi/)"

// Check reports the settings, extensions, MCP commands and system prompt of
// a committed .pi/ folder.
func (r *cfg134) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var out []finding.Finding
	add := func(file string, sev finding.Severity, msg string) {
		out = append(out, finding.Finding{RuleID: "CFG134", Severity: sev, Scope: t.Scope, File: file, Message: msg})
	}
	if s := t.Pi; s != nil {
		if v := parser.PiString(s.ShellPath); v != "" {
			add(t.PiFile, finding.Warn, "pi shellPath is \""+v+"\": every bash tool call runs through this program"+piTrusted+". Leave the shell to the user's settings")
		}
		if v := parser.PiString(s.ShellCommandPrefix); v != "" {
			add(t.PiFile, finding.Warn, "pi shellCommandPrefix is \""+v+"\": pi prepends it to every shell command"+piTrusted+", so it runs with each bash tool call. Leave it to the user's settings")
		}
		if v := parser.PiStrings(s.NpmCommand); len(v) > 0 {
			add(t.PiFile, finding.Warn, "pi npmCommand is \""+strings.Join(v, " ")+"\": pi runs it for every package lookup and install"+piTrusted+". Leave it to the user's settings")
		}
		for _, p := range s.PackageSources() {
			switch {
			case p.Kind != "local" && !p.Pinned:
				add(t.PiFile, finding.Warn, "pi packages names \""+p.Source+"\" with no fixed version: pi installs it at startup"+piTrusted+", and its extensions run in the pi process, so the code that runs follows whatever the registry or branch holds then. Pin an exact npm version or a git tag or commit")
			case p.Kind != "local":
				add(t.PiFile, finding.Info, "pi packages names \""+p.Source+"\": pi installs it at startup"+piTrusted+", and its extensions run in the pi process with no further approval. Review the package before trusting the project")
			case piOutside(p.Source):
				add(t.PiFile, finding.Warn, "pi packages names \""+p.Source+"\", outside the repository: pi loads the package found there on the reader's machine"+piTrusted+". cfgaudit does not read it. Keep project packages in the repository")
			}
		}
		for _, e := range parser.PiStrings(s.Extensions) {
			add(t.PiFile, finding.Warn, "pi extensions names \""+e+"\": pi loads it as a TypeScript module in its own process"+piTrusted+". Review the code before trusting the project")
		}
		if v := parser.PiString(s.DefaultProjectTrust); v != "" {
			add(t.PiFile, finding.Info, "pi defaultProjectTrust is \""+v+"\" in a project file: pi honours it only in the user's own settings, so it has no effect here. Remove it")
		}
	}
	for _, f := range t.PiExtensions {
		add(f, finding.Warn, "pi extension "+filepath.Base(filepath.Dir(f))+"/"+filepath.Base(f)+" runs in the pi process"+piTrusted+": an extension can run commands and block or rewrite the agent's tool calls. Review it before trusting the project")
	}
	for _, c := range t.PiMCPCommands {
		add(t.PiMCPFile, finding.Warn, "pi mcp.json server \""+c.Server+"\" "+c.Field+"."+c.Key+" runs the shell command \""+c.Command+"\" when pi loads the server"+piTrusted+". Put the value in the user's environment instead")
	}
	if t.PiSystemFile != "" {
		add(t.PiSystemFile, finding.Info, "pi .pi/SYSTEM.md replaces pi's built-in system prompt"+piTrusted+", so the repository writes the agent's whole base instructions. The instruction-content rules read it too")
	}
	return out
}

// piOutside reports whether a local package path leaves the repository. "Paths
// in project settings resolve from the project .pi directory" (settings.md),
// so ../x is the repository's x.
func piOutside(src string) bool {
	switch OpenCodeOutside(src) {
	case "home", "absolute":
		return true
	case "parent":
		rel := path.Clean(".pi/" + strings.ReplaceAll(strings.TrimSpace(src), `\`, "/"))
		return rel == ".." || strings.HasPrefix(rel, "../")
	}
	return false
}
