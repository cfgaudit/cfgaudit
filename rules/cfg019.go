// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg019 struct{}

var CFG019 = &cfg019{}

func init() { All = append(All, CFG019) }

func (r *cfg019) ID() string { return "CFG019" }

// shellInterpreters are command basenames that mean the "MCP server" is really an
// inline shell script passed via args, not a self-contained binary or package
// runner. Legitimate servers ship as executables or launch via npx — a raw shell
// invocation is a strong indicator of a malicious/poisoned settings file.
var shellInterpreters = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "fish": true,
	"ksh": true, "csh": true, "tcsh": true,
	"powershell": true, "pwsh": true, "cmd": true,
}

// languageInterpreters run inline code when given an eval flag — node -e, python
// -c, ruby -e, deno eval, … — making the "MCP server" inline code in args rather
// than a real binary. Unlike shells these have legitimate non-inline uses
// (node server.js, python -m pkg), so they are flagged only with an eval flag.
var languageInterpreters = map[string]bool{
	"node": true, "nodejs": true, "deno": true, "bun": true,
	"python": true, "python2": true, "python3": true,
	"ruby": true, "perl": true, "php": true,
}

// inlineEvalFlags are args that make a language interpreter execute code given on
// the command line.
var inlineEvalFlags = map[string]bool{
	"-e": true, "--eval": true, "-c": true, "-p": true, "--print": true, "-E": true, "eval": true,
}

// Check flags MCP servers whose command is really an inline script — a shell
// interpreter (any use), or a language interpreter invoked with an eval flag.
// Covers both settings.json mcpServers and the project .mcp.json (and the
// cross-agent MCP configs, e.g. .vscode/mcp.json).
func (r *cfg019) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		if shell := shellInterpreterName(ref.Server.Command); shell != "" && !shellLaunchesProgram(shell, ref.Server.Args) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG019",
				Severity: finding.Error,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + " runs the shell interpreter \"" + shell +
					"\" — the server is an inline script in args, not a real MCP binary; this is a hallmark of a poisoned settings file. Launch a self-contained executable or a package runner (e.g. npx) instead",
			})
			continue
		}
		if lang := interpreterBasename(ref.Server.Command, languageInterpreters); lang != "" && hasInlineEvalFlag(ref.Server.Args) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG019",
				Severity: finding.Error,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + " runs \"" + lang +
					"\" with an inline-code flag (e.g. -e/-c) — the server is inline code in args, not a real MCP binary; a hallmark of a poisoned settings file. Launch a self-contained executable or a package runner (e.g. npx) instead",
			})
		}
	}
	return findings
}

// shellLaunchesProgram reports whether a shell in an MCP server's command only
// starts a program or a script file rather than running an inline script
// (#822):
//
//   - cmd /c (or /k) followed by one plain command and its arguments, with no
//     &, |, <, > or ^ in them. "cmd /c npx -y pkg" is how an npx server is
//     started on native Windows, and Claude Code's MCP docs give that form.
//   - a POSIX shell given a script path first and no -c flag (alone or in a
//     group such as -lc): "bash scripts/run-mcp.sh". It is the same shape as
//     "node ./dist/index.js", which CFG070 leaves alone on purpose.
//   - PowerShell with -File and none of -Command, -c, -EncodedCommand, -enc,
//     -ec, -e.
func shellLaunchesProgram(shell string, args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch strings.TrimSuffix(strings.ToLower(shell), ".exe") {
	case "cmd":
		switch strings.ToLower(strings.TrimSpace(args[0])) {
		case "/c", "/k":
		default:
			return false
		}
		rest := args[1:]
		if len(rest) == 0 {
			return false
		}
		for _, a := range rest {
			if strings.ContainsAny(a, "&|<>^") {
				return false
			}
		}
		return true
	case "powershell", "pwsh":
		file := false
		for _, a := range args {
			switch strings.ToLower(strings.TrimSpace(a)) {
			case "-command", "-c", "-encodedcommand", "-enc", "-ec", "-e":
				return false
			case "-file", "-f":
				file = true
			}
		}
		return file
	default:
		for i, a := range args {
			a = strings.TrimSpace(a)
			if strings.HasPrefix(a, "--") {
				continue
			}
			if strings.HasPrefix(a, "-") {
				if strings.Contains(a[1:], "c") {
					return i+2 == len(args) && guardedExec(args[i+1])
				}
				continue
			}
			return true // the first operand is the script file
		}
		return false
	}
}

// guardStepRe and execStepRe are the steps of a guarded launch: a test that
// runs nothing ("[ -f \"$HOME/.sentry/mcp.json\" ]", "command -v x >/dev/null"),
// "exit N", and exec of one named program with literal arguments.
var guardStepRe = regexp.MustCompile(`^(?:\[\s[^\]` + "`" + `]*\s\]|test\s[^` + "`" + `]*|command\s+-v\s+[\w.\-]+(?:\s*>\s*/dev/null(?:\s*2>&1)?)?|exit(?:\s+\d+)?|true|false)$`)
var guardSplitRe = regexp.MustCompile(`&&|\|\||;`)
var execStepRe = regexp.MustCompile(`^exec\s+[\w./\-]+(?:\s+[\w./=:@,\-"']+)*$`)

// guardedExec reports whether a -c script only checks a condition and then
// execs one named program: "[ -f \"$HOME/.sentry/mcp.json\" ] && exec
// sentry-mcp --organization-slug hackerspub || exit 0" starts the server only
// where it is configured (#874). Anything else in the script, a substitution,
// a pipe or a redirect, keeps it an inline script.
func guardedExec(script string) bool {
	rest := strings.NewReplacer("||", " ", "&&", " ", ">/dev/null", " ", "> /dev/null", " ", "2>&1", " ").Replace(script)
	if strings.ContainsAny(rest, "|<>`\n") || strings.Contains(script, "$(") {
		return false
	}
	execs, guards := 0, 0
	for _, step := range guardSplitRe.Split(script, -1) {
		step = strings.TrimSpace(step)
		switch {
		case execStepRe.MatchString(step):
			execs++
		case guardStepRe.MatchString(step):
			guards++
		default:
			return false
		}
	}
	// A bare "exec real-mcp-server" has no condition to check and is still
	// the shell-wrapped server the rule reports.
	return execs == 1 && guards > 0
}

// hasInlineEvalFlag reports whether args contain a flag that makes an interpreter
// execute inline code (-e/--eval/-c/-p/--print/-E/eval, or --eval=/--print=).
func hasInlineEvalFlag(args []string) bool {
	for _, a := range args {
		a = strings.TrimSpace(a)
		if inlineEvalFlags[a] || strings.HasPrefix(a, "--eval=") || strings.HasPrefix(a, "--print=") {
			return true
		}
	}
	return false
}

// shellInterpreterName returns the matched shell name when command's basename is
// a known shell interpreter, else "".
func shellInterpreterName(command string) string {
	return interpreterBasename(command, shellInterpreters)
}

// interpreterBasename returns command's basename when it is in set (case-
// insensitive, with an optional .exe suffix), else "". The basename is split on
// both / and \ so Windows paths match on any OS.
func interpreterBasename(command string, set map[string]bool) string {
	if command == "" {
		return ""
	}
	base := command
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(strings.ToLower(base), ".exe")
	if set[base] {
		return base
	}
	return ""
}
