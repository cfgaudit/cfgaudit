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
	// Partial is set when the script is over the read limit and Content holds
	// only its first and last bytes (CFG119 only, #1270); Size is then the
	// file's full size.
	Partial bool
	Size    int64
	// Skill is the SKILL.md this script ships with, for a script under a
	// skill directory that no auto-run command starts (#987): the agent runs
	// it when the skill tells it to.
	Skill string
	// Shell marks a shell script that its name does not show: a Cline hook
	// is named after its event, with no extension (#1523).
	Shell bool
	// ZeroClick is set when a command that runs as soon as the repository is
	// opened or a session starts launches the script (#1650): a SessionStart
	// hook or a VS Code folderOpen task. See ZeroClickLaunch.
	ZeroClick bool
	// HiddenBy names the agent ignore file line (.claudeignore, .cursorignore,
	// .geminiignore, .aiexclude) that keeps the agent from reading the script
	// or one of its launcher files, as "file:line (pattern)" (#1650).
	HiddenBy string
}

// zeroClickLabelRe matches the label of a launch command that runs as soon as
// the repository is opened or a session starts, before the user asks for
// anything: a SessionStart hook of any agent and a VS Code folderOpen task.
var zeroClickLabelRe = regexp.MustCompile(`(?i)(?:^|\s)hooks\.session_?start\s|^VS Code folderOpen task `)

// ZeroClickLaunch reports whether the launch command with this label runs
// when the repository is opened or a session starts (#1650). A frontmatter
// hook runs only once the agent picks that skill or subagent.
func ZeroClickLaunch(label string) bool {
	return zeroClickLabelRe.MatchString(label) && !strings.Contains(label, "frontmatter")
}

// isShell reports whether the script is a shell script.
func (s LaunchedScript) isShell() bool {
	return s.Shell || shellScriptRe.MatchString(s.File)
}

// ClineHook is one Cline hook file: its path relative to the project, in
// forward slashes, and the event it runs on.
type ClineHook struct {
	Path, Event string
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
		if s.HookInput {
			continue
		}
		out = append(out, LaunchCommand{Label: s.Label, File: s.File, Command: s.Command})
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
		if s.Via != "" || s.Partial || !s.isShell() {
			continue
		}
		for _, l := range scriptCommandLines(s.Content) {
			sites = append(sites, commandSite{Label: s.Label, File: s.File, Command: maskMessageQuotes(l.text), Line: l.line, Raw: l.text})
		}
	}
	return sites
}

// scriptLine is one command of a script and the line it starts on.
type scriptLine struct {
	text string
	line int
}

var (
	// arrayOpenRe is an array assignment whose elements follow on the next
	// lines: PROTECTED=(
	arrayOpenRe = regexp.MustCompile(`^(?:(?:local|declare|readonly|export)(?:\s+-\w+)*\s+)?\w+\+?=\([^)]*$`)
	// heredocRe is a here-document and its delimiter word; a here-string
	// (<<<) is not one.
	heredocRe = regexp.MustCompile(`(?:^|[^<])<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)['"]?`)
	// heredocRunsRe is a command before << that runs its input: the body is
	// then a script of its own.
	heredocRunsRe = regexp.MustCompile(`\b(?:bash|sh|zsh|ssh|python3?|node|perl|eval)\b`)
)

// scriptCommandLines splits a shell script into its commands, as the shell
// reads them (#1365): a line ending in a backslash continues on the next one,
// the elements of a multi-line array belong to its assignment, and a
// here-document's body is data unless the command it feeds runs it. Blank
// lines and comments are left out.
func scriptCommandLines(content string) []scriptLine {
	lines := strings.Split(content, "\n")
	var out []scriptLine
	for i := 0; i < len(lines); i++ {
		start := i
		text := strings.TrimSpace(lines[i])
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		for strings.HasSuffix(text, "\\") && i+1 < len(lines) {
			i++
			text = strings.TrimSuffix(text, "\\") + " " + strings.TrimSpace(lines[i])
		}
		if arrayOpenRe.MatchString(text) {
			for !strings.Contains(text, ")") && i+1 < len(lines) {
				i++
				if l := strings.TrimSpace(lines[i]); l != "" && !strings.HasPrefix(l, "#") {
					text += " " + l
				}
			}
		}
		out = append(out, scriptLine{text: text, line: start + 1})
		m := heredocRe.FindStringSubmatchIndex(text)
		if m == nil {
			continue
		}
		word := text[m[4]:m[5]]
		runs := heredocRunsRe.MatchString(text[:m[0]])
		for i+1 < len(lines) {
			i++
			l := strings.TrimSpace(lines[i])
			if l == word {
				break
			}
			if runs && l != "" && !strings.HasPrefix(l, "#") {
				out = append(out, scriptLine{text: l, line: i + 1})
			}
		}
	}
	return out
}

// arrayLiteralRe is the start of an array literal: NAME=( or NAME+=(.
var arrayLiteralRe = regexp.MustCompile(`^\w+\+?=\(`)

// messageCommands print or match their quoted arguments instead of running
// them: an install hint in an echo, a guard script's grep pattern for the
// command it blocks (#1365).
var messageCommands = map[string]bool{
	"echo": true, "printf": true, "print": true, "logger": true,
	"log": true, "info": true, "warn": true, "warning": true, "error": true, "err": true,
	"die": true, "fail": true, "fatal": true, "msg": true, "note": true, "say": true,
	"hint": true, "report": true, "notify": true, "debug": true,
	"grep": true, "egrep": true, "fgrep": true, "rg": true, "ag": true, "ack": true,
}

// maskMessageQuotes blanks the contents of the quoted strings that a
// message command prints or matches, of an array literal's elements, and of
// the pattern after =~ in [[ ]].
// A $(...) or backtick substitution inside double quotes runs, so it is kept.
// The quotes and the length stay, so the rest of the command reads as before.
func maskMessageQuotes(cmd string) string {
	b := []byte(cmd)
	segStart := 0
	for i := 0; i < len(b); i++ {
		switch c := b[i]; c {
		case '|', ';', '&':
			segStart = i + 1
		case '\\':
			i++
		case '\'', '"':
			end := closingQuote(cmd, i)
			if end < 0 {
				return string(b)
			}
			if masksQuotes(cmd[segStart:i]) {
				blankQuoted(b, i+1, end, c == '"')
			}
			i = end
		}
	}
	return string(b)
}

// closingQuote is the index of the quote that closes the one at open, or -1.
func closingQuote(s string, open int) int {
	q := s[open]
	for j := open + 1; j < len(s); j++ {
		switch {
		case q == '"' && s[j] == '\\':
			j++
		case s[j] == q:
			return j
		}
	}
	return -1
}

// masksQuotes reports whether the quoted strings after seg, the start of a
// command, are what a message command prints or matches, or the elements of
// an array literal: a guard hook's list of protected names is data.
func masksQuotes(seg string) bool {
	if strings.Contains(seg, "[[") && strings.Contains(seg, "=~") {
		return true
	}
	for _, f := range strings.Fields(seg) {
		if arrayLiteralRe.MatchString(f) {
			return true
		}
		f = strings.TrimLeft(f, "({!")
		switch {
		case f == "" || f == "if" || f == "then" || f == "else" || f == "elif" || f == "do" || f == "while" || f == "until" || f == "sudo" || f == "command" || f == "builtin":
			continue
		case strings.Contains(f, "=") && !strings.HasPrefix(f, "-"):
			continue
		}
		return messageCommands[f]
	}
	return false
}

// blankQuoted replaces b[from:to] with spaces, keeping a $(...) or backtick
// substitution when the string is double-quoted.
func blankQuoted(b []byte, from, to int, double bool) {
	depth := 0
	tick := false
	for j := from; j < to; j++ {
		switch {
		case double && !tick && b[j] == '$' && j+1 < to && b[j+1] == '(':
			depth++
			j++
			continue
		case double && depth > 0 && b[j] == ')':
			depth--
			continue
		case double && depth == 0 && b[j] == '`':
			tick = !tick
			continue
		}
		if depth == 0 && !tick {
			b[j] = ' '
		}
	}
}

// shellScriptRe matches the file name of a shell script.
var shellScriptRe = regexp.MustCompile(`\.(?:sh|bash|zsh)$`)
