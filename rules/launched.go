// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"sort"
	"strings"
)

// LaunchedScript is a file from the scanned repository that a command running
// without the user asking for it starts: a hook, a credential helper, a VS
// Code task that runs on folder open, or an MCP server launch (#1217). The
// command-content rules read the command string only, so a payload moved into
// a committed script used to pass them all; cfgaudit now reads the script and
// runs the rules whose patterns mean the same in a script as on a command
// line. Nothing is executed.
type LaunchedScript struct {
	// Label names the script and what starts it, phrased like a command
	// site's label so rules can append their verb: `script .claude/x.mjs,
	// started by the hooks.SessionStart command,`.
	Label string
	// File is the script's path.
	File string
	// Content is the script's text.
	Content string
	// Launchers are the config files whose commands start the script, sorted;
	// more than one tool starting the same script is a persistence signal
	// for CFG119.
	Launchers []string
	// Via is the launched script that names and runs this file, when it was
	// reached one step further (CFG119 only); "" for a script a command
	// starts directly.
	Via string
}

// LaunchCommand is one auto-run command that may start a repository script.
type LaunchCommand struct {
	Label, File, Command string
}

// LaunchCommands returns the commands of t that run without the user asking:
// every command site, each VS Code task that runs on folder open, and each MCP
// server launch.
func LaunchCommands(t *Target) []LaunchCommand {
	if t == nil {
		return nil
	}
	var out []LaunchCommand
	for _, s := range commandSites(t) {
		out = append(out, LaunchCommand(s))
	}
	if vt := t.VSCodeTasks; vt != nil {
		for _, task := range vt.Tasks {
			if task.Command != "" && task.RunOptions != nil && task.RunOptions.RunOn == "folderOpen" {
				out = append(out, LaunchCommand{Label: "VS Code folderOpen task \"" + task.Label + "\" command", File: t.VSCodeTasksFile, Command: task.Command})
			}
		}
	}
	names := make([]string, 0, len(t.ProjectMCP))
	for n := range t.ProjectMCP {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		srv := t.ProjectMCP[n]
		if srv.Command != "" {
			out = append(out, LaunchCommand{Label: "mcpServers." + n + " command", File: t.ProjectMCPFile, Command: strings.TrimSpace(srv.Command + " " + strings.Join(srv.Args, " "))})
		}
	}
	return out
}

// commandSitesWithScripts is commandSites plus the lines of the shell scripts
// the target's auto-run commands start (#1217), each line a command of its
// own and comment lines left out. The rules match one command line; run over
// a whole file they joined a "printenv" in a guard hook's list of allowed
// commands with a curl forty lines further down. JavaScript, Python and
// PowerShell files are read by CFG119 only, whose markers are made for whole
// files. Only the rules whose pattern means the same thing in a script as on a
// command line use this: a reverse shell,
// curl piped into a shell, persistence, SSH key reads, an environment dump to
// the network, a hardcoded secret, a DNS-encoded exfiltration, audit-trail
// destruction and credential-store reads. Rules about the command line itself
// (variable interpolation, substitutions, rm -rf, ShellCheck, package names,
// Docker flags) keep reading command sites only, since a script is full of
// variables and substitutions by nature.
func commandSitesWithScripts(t *Target) []commandSite {
	sites := commandSites(t)
	if t == nil {
		return sites
	}
	for _, s := range t.LaunchedScripts {
		if s.Via != "" || !shellScriptRe.MatchString(s.File) {
			continue
		}
		for _, line := range strings.Split(s.Content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			sites = append(sites, commandSite{Label: s.Label, File: s.File, Command: line})
		}
	}
	return sites
}

// shellScriptRe matches the file name of a shell script.
var shellScriptRe = regexp.MustCompile(`\.(?:sh|bash|zsh)$`)
