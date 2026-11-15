// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg145 struct{}

// CFG145 reports a Claude Code hook whose output carries the whole
// environment or a secret-named variable into the model's context (#1685).
var CFG145 = &cfg145{}

func init() { All = append(All, CFG145) }

func (r *cfg145) ID() string { return "CFG145" }

// Where Claude Code 2.1.325 sends a hook's stdout on exit code 0, from the
// event descriptions in its binary.
var (
	// hookContextEvents put stdout into the model's context: "stdout shown
	// to Claude" (PostModelSwitch: "on the next request").
	hookContextEvents = map[string]bool{"SessionStart": true, "UserPromptSubmit": true, "UserPromptExpansion": true, "PostModelSwitch": true}
	// hookTranscriptEvents show stdout in transcript mode (Ctrl+O) only.
	hookTranscriptEvents = map[string]bool{"PostToolUse": true, "PostToolUseFailure": true, "PermissionDenied": true}
)

// claudeHookEventRe reads the event of a Claude Code hook site from its label:
// "hooks.SessionStart command", "skill frontmatter hooks.Stop command", and a
// script's "script x.sh, started by the hooks.SessionStart command,". Other
// agents' hook labels carry their name ("Gemini hooks.…") and do not match.
var claudeHookEventRe = regexp.MustCompile(`(?:^|started by the |frontmatter )hooks\.([A-Za-z]+) command`)

func (r *cfg145) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var out []finding.Finding
	seen := map[string]bool{}
	for _, site := range commandSitesWithScripts(t) {
		m := claudeHookEventRe.FindStringSubmatch(site.Label)
		if m == nil || site.PowerShell {
			continue
		}
		event := m[1]
		raw := site.raw()
		what, ok := hookOutputLeak(raw)
		xtrace := site.Line > 0 && hookContextEvents[event] && xtraceRe.MatchString(raw)
		var sev finding.Severity
		var msg string
		switch {
		case ok && (hookContextEvents[event] || strings.Contains(raw, "additionalContext")):
			sev = finding.Error
			via := "the stdout of a " + event + " hook"
			if !hookContextEvents[event] {
				via = "a hook's additionalContext"
			}
			msg = site.Label + " prints " + what + ": Claude Code adds " + via + " to the model's context, so the value goes to the model provider and into the session transcript. Print only what the session needs, never the environment or a secret"
		case ok && hookTranscriptEvents[event]:
			sev = finding.Warn
			msg = site.Label + " prints " + what + ": Claude Code shows the stdout of a " + event + " hook to anyone who opens transcript mode (Ctrl+O). Print only what the session needs, never the environment or a secret"
		case xtrace:
			sev = finding.Warn
			msg = site.Label + " turns on xtrace (set -x): the shell prints every command with its variables expanded to stderr, which Claude Code shows to the user when a " + event + " hook fails, secrets included. Remove set -x, or turn it off around commands that use a secret"
		default:
			continue
		}
		key := site.File + "\x00" + msg
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, finding.Finding{RuleID: "CFG145", Severity: sev, File: site.File, Line: site.Line, Message: msg})
	}
	return out
}

// xtraceRe is a set -x, set -o xtrace, or a set flag bundle with x.
var xtraceRe = regexp.MustCompile(`(?:^|[;&|]\s*)set\s+(?:-[a-wyzA-Z]*x[a-zA-Z]*|-o\s+xtrace)\b`)

// hookPipeline is the commands one pipeline joins with |.
type hookPipeline []string

// hookPipelines splits a command line into pipelines at ;, &, &&, || and
// newlines outside quotes, and each pipeline into its | commands.
func hookPipelines(s string) []hookPipeline {
	var out []hookPipeline
	var cur hookPipeline
	var quote byte
	start := 0
	cut := func(i int) {
		cur = append(cur, s[start:i])
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '|' && i+1 < len(s) && s[i+1] == '|', c == '&' && i+1 < len(s) && s[i+1] == '&':
			cut(i)
			out, cur = append(out, cur), nil
			i++
			start = i + 1
		case c == '|':
			cut(i)
			start = i + 1
		case c == ';' || c == '&' || c == '\n':
			cut(i)
			out, cur = append(out, cur), nil
			start = i + 1
		}
	}
	cut(len(s))
	return append(out, cur)
}

// hookOutputLeak reports what a command writes to stdout that it should not:
// the whole environment, or a secret-named variable. "" and false when it
// writes neither, or sends the output somewhere other than stdout.
func hookOutputLeak(cmd string) (string, bool) {
	for _, p := range hookPipelines(cmd) {
		if len(p) == 0 {
			continue
		}
		if !pipelineReachesStdout(p) {
			continue
		}
		first := shellWords(p[0])
		if len(first) == 0 {
			continue
		}
		if dump := envDumpCommand(first); dump != "" {
			if len(p) > 1 && !filterKeepsSecrets(p[1:]) {
				continue
			}
			return "the whole environment (" + dump + ")", true
		}
		if len(p) > 1 {
			continue // echo "$TOKEN" | docker login --password-stdin
		}
		if name := printedSecret(p[0], first); name != "" {
			return "$" + name, true
		}
	}
	if m := substDumpRe.FindStringSubmatch(cmd); m != nil {
		return "the whole environment ($(" + m[1] + "))", true
	}
	return "", false
}

// substDumpRe is an environment dump inside a substitution that is printed:
// echo "$(env)", jq --arg c "$(printenv)".
var substDumpRe = regexp.MustCompile(`(?:\becho|\bprintf|\bjq|\bcat)\b[^;&|\n]*\$\(\s*(env|printenv|export -p)\s*\)`)

// envDumpCommand returns the command when words dump the whole environment:
// printenv with no name, env with no command to run, export -p, or cat of a
// /proc environ file.
func envDumpCommand(words []string) string {
	name := executableName(words[0])
	args := words[1:]
	switch name {
	case "printenv":
		for _, a := range args {
			if !strings.HasPrefix(a, "-") && !isRedirect(a) {
				return ""
			}
		}
		return "printenv"
	case "env":
		for _, a := range args {
			switch {
			case isRedirect(a), a == "-0", a == "--null":
			case strings.HasPrefix(a, "-"), strings.Contains(a, "="):
				return "" // env -i cmd, env FOO=bar cmd
			default:
				return "" // a command to run
			}
		}
		return "env"
	case "export":
		if len(args) > 0 && args[0] == "-p" {
			return "export -p"
		}
	case "cat", "strings", "xargs":
		for _, a := range args {
			if procEnvironRe.MatchString(a) {
				return name + " " + a
			}
		}
	}
	return ""
}

// procEnvironRe is a process's environment file under /proc.
var procEnvironRe = regexp.MustCompile(`^/proc/(?:self|\*|\$\$|\$\w+|\d+)/environ$`)

// isRedirect reports a word that starts a redirection: >file, 2>&1, <in.
func isRedirect(w string) bool {
	return strings.HasPrefix(w, ">") || strings.HasPrefix(w, "<") || strings.HasPrefix(w, "1>") || strings.HasPrefix(w, "2>") || strings.HasPrefix(w, "&>")
}

// pipelineReachesStdout reports whether the last command of a pipeline still
// writes to stdout: no redirection of stdout to a file, /dev/null or stderr,
// and no network tool at its end.
func pipelineReachesStdout(p hookPipeline) bool {
	for _, seg := range p {
		words := shellWords(seg)
		for _, w := range words {
			if strings.HasPrefix(w, ">") || strings.HasPrefix(w, "1>") || strings.HasPrefix(w, "&>") {
				return false
			}
		}
		if len(words) > 0 && hookNetworkTools[executableName(words[0])] {
			return false // CFG038
		}
	}
	return true
}

var hookNetworkTools = map[string]bool{"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "socat": true}

// passThroughTools pass the environment dump on to stdout, whole or a slice.
var passThroughTools = map[string]bool{"sort": true, "uniq": true, "head": true, "tail": true, "tee": true, "cat": true, "sed": true, "awk": true, "cut": true, "column": true, "less": true, "more": true, "tr": true}

// secretWordRe is a grep pattern that selects secrets.
var secretWordRe = regexp.MustCompile(`(?i)token|secret|key|pass|auth|cred`)

// filterKeepsSecrets reports whether the commands after an environment dump
// still print secrets: pass-through tools do, a grep for a non-secret name
// (grep ^PATH=), a count (wc, grep -c) or a quiet grep does not.
func filterKeepsSecrets(rest []string) bool {
	for _, seg := range rest {
		words := shellWords(seg)
		if len(words) == 0 {
			return false
		}
		name := executableName(words[0])
		if passThroughTools[name] {
			continue
		}
		if name != "grep" && name != "egrep" && name != "rg" {
			return false
		}
		invert, pattern := false, ""
		for _, w := range words[1:] {
			switch {
			case w == "-v" || w == "--invert-match":
				invert = true
			case w == "-c" || w == "-q" || w == "--count" || w == "--quiet" || w == "-l":
				return false
			case strings.HasPrefix(w, "-"):
			case pattern == "":
				pattern = w
			}
		}
		if !invert && !secretWordRe.MatchString(pattern) {
			return false
		}
	}
	return true
}

// varRefRe is a variable reference: $NAME, ${NAME}, ${NAME:-x}, ${#NAME}.
var varRefRe = regexp.MustCompile(`\$(?:\{(#?)([A-Za-z_][A-Za-z0-9_]*)([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*))`)

// printedSecret returns the secret-named variable an echo, printf or printenv
// prints: echo "token: $GITHUB_TOKEN", printenv API_KEY. A reference in single
// quotes is not expanded; ${#NAME} prints a length and ${NAME:+x} a word.
func printedSecret(seg string, words []string) string {
	switch executableName(words[0]) {
	case "printenv":
		for _, a := range words[1:] {
			if !strings.HasPrefix(a, "-") && secretVarName(a) {
				return a
			}
		}
		return ""
	case "echo", "printf":
	default:
		return ""
	}
	for _, m := range varRefRe.FindAllStringSubmatch(blankSingleQuoted(seg), -1) {
		name, mod := m[4], m[3]
		if m[2] != "" {
			name = m[2]
		}
		if m[1] == "#" || strings.HasPrefix(mod, ":+") || strings.HasPrefix(mod, "+") {
			continue
		}
		if secretVarName(name) {
			return name
		}
	}
	return ""
}

// secretVarName is a variable name that holds a secret: one secretKeyName
// knows, or a bare suffix such as API_KEY or TOKEN.
func secretVarName(name string) bool {
	return secretKeyName(name) || hasSecretSuffix("_"+name)
}

// blankSingleQuoted blanks the text inside single quotes, where the shell
// expands nothing.
func blankSingleQuoted(s string) string {
	b := []byte(s)
	var quote byte
	for i, c := range b {
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				b[i] = ' '
			}
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		}
	}
	return string(b)
}
