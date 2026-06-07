package rules

import (
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
		if shell := shellInterpreterName(ref.Server.Command); shell != "" {
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
