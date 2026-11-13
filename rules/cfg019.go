// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
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
	return append(findings, zedLSPInlineScripts(t)...)
}

// zedLSPInlineScripts applies the same two checks to the language servers a
// committed .zed/settings.json starts (#996, CVE-2025-68432): lsp.<name>.binary
// with a shell running an inline script, or an interpreter with an
// inline-code flag. Zed starts them on worktree trust.
func zedLSPInlineScripts(t *Target) []finding.Finding {
	if t.ZedSettings == nil {
		return nil
	}
	var out []finding.Finding
	for _, name := range sortedKeys2(t.ZedSettings.LSP) {
		b := t.ZedSettings.LSP[name].Binary
		if b == nil || strings.TrimSpace(b.Path) == "" {
			continue
		}
		label := "lsp." + name + ".binary"
		if shell := shellInterpreterName(b.Path); shell != "" && !shellLaunchesProgram(shell, b.Arguments) {
			out = append(out, finding.Finding{RuleID: "CFG019", Severity: finding.Error, File: t.ZedSettingsFile, Key: label,
				Message: label + " runs the shell interpreter \"" + shell + "\" — the language server is an inline script in arguments, not a real server binary; Zed starts it once the worktree is trusted. Point path at the server executable instead"})
			continue
		}
		if lang := interpreterBasename(b.Path, languageInterpreters); lang != "" && hasInlineEvalFlag(b.Arguments) {
			out = append(out, finding.Finding{RuleID: "CFG019", Severity: finding.Error, File: t.ZedSettingsFile, Key: label,
				Message: label + " runs \"" + lang + "\" with an inline-code flag (e.g. -e/-c) — the language server is inline code in arguments; Zed starts it once the worktree is trusted. Point path at the server executable instead"})
		}
	}
	return out
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
//
// cmdLaunchers are the programs besides the package runners that a cmd /c
// may start for an MCP server (#997).
var cmdLaunchers = map[string]bool{
	"node": true, "npm": true, "python": true, "python3": true, "py": true, "deno": true, "bun": true,
	"uv": true, "docker": true, "podman": true, "java": true, "dotnet": true,
}

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
		// Only a package runner or a language runtime after /c (#997):
		// "cmd /c npx -y pkg" is how Windows starts an npx server, while
		// "cmd.exe /c <any binary>" let a committed .cursor/mcp.json run
		// anything (CVE-2025-54136).
		f := strings.Fields(rest[0])
		if len(f) == 0 {
			return false
		}
		prog := strings.TrimSuffix(strings.ToLower(filepath.Base(strings.ReplaceAll(f[0], `\`, "/"))), ".exe")
		prog = strings.TrimSuffix(strings.TrimSuffix(prog, ".cmd"), ".bat")
		if !npmPackageRunners[prog] && !pyPackageRunners[prog] && !cmdLaunchers[prog] {
			return false
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
		// pwsh's default positional parameter is -File, so "pwsh
		// ./scripts/start.ps1" runs a script file (#1183). Windows PowerShell
		// 5.1 defaults to -Command and is not changed without a measurement.
		if !file && strings.TrimSuffix(strings.ToLower(shell), ".exe") == "pwsh" {
			file = strings.HasSuffix(strings.ToLower(pwshFirstOperand(args)), ".ps1")
		}
		return file
	default:
		login := false
		for i, a := range args {
			a = strings.TrimSpace(a)
			if a == "--login" {
				login = true
				continue
			}
			if strings.HasPrefix(a, "--") {
				continue
			}
			if strings.HasPrefix(a, "-") {
				if strings.Contains(a[1:], "l") {
					login = true
				}
				if strings.Contains(a[1:], "c") {
					return i+2 == len(args) && guardedExec(args[i+1], login)
				}
				continue
			}
			return true // the first operand is the script file
		}
		return false
	}
}

// pwshValueFlags are the pwsh parameters that take a value, so the word after
// them is not the script operand.
var pwshValueFlags = map[string]bool{
	"-executionpolicy": true, "-ex": true, "-ep": true, "-workingdirectory": true, "-wd": true,
	"-configurationname": true, "-settingsfile": true, "-outputformat": true, "-of": true,
	"-inputformat": true, "-if": true, "-windowstyle": true, "-w": true, "-custompipename": true,
}

// pwshFirstOperand returns pwsh's first positional argument, or "".
func pwshFirstOperand(args []string) string {
	for i := 0; i < len(args); i++ {
		a := strings.ToLower(strings.TrimSpace(args[i]))
		if strings.HasPrefix(a, "-") {
			if pwshValueFlags[a] {
				i++
			}
			continue
		}
		return strings.TrimSpace(args[i])
	}
	return ""
}

// guardStepRe is a step of a guarded launch that runs nothing: a test ("[ -f
// \"$HOME/.sentry/mcp.json\" ]", "command -v x >/dev/null"), "exit N". The
// program the launch starts is programStepRe.
var guardStepRe = regexp.MustCompile(`^(?:\[\s[^\]` + "`" + `]*\s\]|test\s[^` + "`" + `]*|command\s+-v\s+[\w.\-]+(?:\s*>\s*/dev/null(?:\s*2>&1)?)?|exit(?:\s+\d+)?|true|false)$`)
var guardSplitRe = regexp.MustCompile(`&&|\|\||;`)

// cdStepRe is a change to a literal directory, which runs nothing (#1183).
var cdStepRe = regexp.MustCompile(`^cd\s+[\w./~\-]+$`)

// programStepRe is one named program with literal arguments, run with exec,
// or without it after NAME=value assignments (#1665):
// "exec sentry-mcp --org x", "LORE_SUPPRESS_DEPRECATIONS='1' lore mcp".
var programStepRe = regexp.MustCompile(`^(?:[A-Za-z_]\w*=` + envValue + `\s+)*(?:exec\s+)?[\w./\-]+(?:\s+[\w./=:@,\-"'][\w./=:@,\-"'#]*)*$`)

// envValue is a value an assignment gives that runs nothing: literal text,
// single-quoted text, or double-quoted text whose only expansion is $HOME
// (#1665): LORE_CONFIG_ROOT="${HOME}"'/.lore'.
const envValue = `(?:[\w./:@,\-]+|'[^'$` + "`" + `]*'|"(?:[\w./:@,\- ]|\$\{?HOME\}?)*")+`

// launchEnvAssignRe is one NAME=value word of programStepRe.
var launchEnvAssignRe = regexp.MustCompile(`^[A-Za-z_]\w*=` + envValue + `$`)

// rootAssignRe is a variable set to the repository root, which
// normalizeRepoRoot has turned into ROOT: workspace=$(git rev-parse
// --show-toplevel).
var rootAssignRe = regexp.MustCompile(`^[A-Za-z_]\w*=ROOT$`)

// repoRootRefRe is the repository root or the project directory written in
// the script, quoted, as a whole word or before a path (#1665):
// "$(git rev-parse --show-toplevel)", "${CLAUDE_PROJECT_DIR:-.}",
// "$CLAUDE_PROJECT_DIR/scripts/x", "$PWD". Group 1 is the path after it.
var repoRootRefRe = regexp.MustCompile(`"?\$(?:\(git rev-parse --show-toplevel\)|\{CLAUDE_PROJECT_DIR(?::?-\.?)?\}|CLAUDE_PROJECT_DIR\b|\{PWD\}|PWD\b)((?:/[\w./\-]*)?)"?`)

// rootVarDefRe finds a variable assigned the repository root.
var rootVarDefRe = regexp.MustCompile(`(?:^|[;&|]\s*)([A-Za-z_]\w*)="?ROOT"?(?:\s*(?:&&|\|\||;)|$)`)

// normalizeRepoRoot writes the repository root as ROOT, so that the steps
// that only prepare where the server runs read as literals: cd "$(git
// rev-parse --show-toplevel)", cd "${CLAUDE_PROJECT_DIR:-.}", exec
// "$CLAUDE_PROJECT_DIR/scripts/x", and a variable set to the root and used
// only quoted ("$workspace"). A root variable used unquoted is not one: false.
func normalizeRepoRoot(script string) (string, bool) {
	script = repoRootRefRe.ReplaceAllString(script, `ROOT$1`)
	for _, m := range rootVarDefRe.FindAllStringSubmatch(script, -1) {
		name := regexp.QuoteMeta(m[1])
		script = regexp.MustCompile(`="ROOT"`).ReplaceAllString(script, `=ROOT`)
		script = regexp.MustCompile(`"\$(?:`+name+`\b|\{`+name+`\})((?:/[\w./\-]*)?)"`).ReplaceAllString(script, `ROOT$1`)
		if regexp.MustCompile(`\$(?:` + name + `\b|\{` + name + `\})`).MatchString(script) {
			return script, false
		}
	}
	return script, true
}

// repoRootPrefixRe is `$(git rev-parse --show-toplevel)` as the start of the
// exec target's path, quoted or not (#1183).
var repoRootPrefixRe = regexp.MustCompile(`"?\$\(git rev-parse --show-toplevel\)/([\w./\-]+)"?`)

// guardedExec reports whether a -c script only checks a condition and then
// execs one named program: "[ -f \"$HOME/.sentry/mcp.json\" ] && exec
// sentry-mcp --organization-slug hackerspub || exit 0" starts the server only
// where it is configured (#874). Anything else in the script, a substitution,
// a pipe or a redirect, keeps it an inline script.
//
// A bare exec also counts when the wrapper only prepares where it runs
// (#1183): a login shell for PATH ("bash -l -c 'exec npx -y pkg'"), a leading
// "cd <literal dir> &&", or a target under "$(git rev-parse --show-toplevel)/".
func guardedExec(script string, login bool) bool {
	setup := login
	if repoRootPrefixRe.MatchString(script) {
		script = repoRootPrefixRe.ReplaceAllString(script, `ROOT/$1`)
		setup = true
	}
	normalized, ok := normalizeRepoRoot(script)
	if !ok {
		return false
	}
	if normalized != script {
		// The script moves to or runs from the repository root, as
		// "$(git rev-parse --show-toplevel)/" does above (#1183, #1665).
		script, setup = normalized, true
	}
	rest := strings.NewReplacer("||", " ", "&&", " ", ">/dev/null", " ", "> /dev/null", " ", "2>&1", " ").Replace(script)
	if strings.ContainsAny(rest, "|<>`\n") || strings.Contains(script, "$(") {
		return false
	}
	execs, guards := 0, 0
	for _, step := range guardSplitRe.Split(script, -1) {
		step = strings.TrimSpace(step)
		switch {
		case guardStepRe.MatchString(step):
			guards++
		case (cdStepRe.MatchString(step) || rootAssignRe.MatchString(step)) && execs == 0:
			setup = true
		case programStepRe.MatchString(step):
			// exec of another shell, or of an interpreter with inline code, is
			// still an inline script. A program run without exec is the last
			// command of the script, which the shell runs the same way.
			f := strings.Fields(step)
			envs, exec := 0, false
			for len(f) > 0 && (launchEnvAssignRe.MatchString(f[0]) || f[0] == "exec") {
				if f[0] == "exec" {
					exec = true
				} else {
					envs++
					setup = true // the environment the program gets (#1665)
				}
				f = f[1:]
			}
			// Without exec, only a program that gets an environment counts:
			// "bash -lc 'echo hi'" stays an inline script.
			if !exec && envs == 0 {
				return false
			}
			if len(f) == 0 || f[0] == "cd" || shellInterpreterName(f[0]) != "" || (interpreterBasename(f[0], languageInterpreters) != "" && hasInlineEvalFlag(f[1:])) {
				return false
			}
			execs++
		default:
			return false
		}
	}
	// A bare "exec real-mcp-server" with no condition and no setup is still
	// the shell-wrapped server the rule reports.
	return execs == 1 && (guards > 0 || setup)
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
