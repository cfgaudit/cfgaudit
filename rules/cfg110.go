package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg110 struct{}

// CFG110 reports a Claude Code settings env block that injects code into the
// shells Claude Code starts.
var CFG110 = &cfg110{}

func init() { All = append(All, CFG110) }

func (r *cfg110) ID() string { return "CFG110" }

// shellPrefixVar is the Claude Code variable that wraps every shell command it
// runs. Documented as a command prefix "to wrap all bash commands"; measured on
// 2.1.288, a value from a project settings env was invoked for a SessionStart
// hook and for a Bash tool call, each time with the whole command as its one
// argument.
const shellPrefixVar = "CLAUDE_CODE_SHELL_PREFIX"

// Check reports interpreter, dynamic-linker, JVM, .NET and git variables set in
// a settings file's env block, plus CLAUDE_CODE_SHELL_PREFIX.
//
// Claude Code applies the settings env block to every session, so a value here
// reaches every hook and every Bash tool call. Measured on 2.1.288 with a
// scratch HOME and a trusted project whose .claude/settings.json env set
// BASH_ENV, DOTNET_STARTUP_HOOKS, JAVA_TOOL_OPTIONS, GIT_SSH_COMMAND,
// GIT_CONFIG_COUNT/KEY_0/VALUE_0 and CLAUDE_CODE_SHELL_PREFIX: every one of
// them was in a SessionStart hook's environment (none stripped in project
// scope), the BASH_ENV file was sourced, the core.fsmonitor command ran on a
// `git status`, and the prefix script wrapped the hook and the Bash tool call.
// Project env applies only after the workspace trust dialog, the same gate as
// project hooks, which a reader accepting a clone does not read as "and run
// this script before every command".
//
// The classifier is CFG020's, shared with CFG107: the same attack on a third
// surface. LD_LIBRARY_PATH / DYLD_LIBRARY_PATH get CFG107's gate, since this
// block prepares ordinary build and test shells too.
//
// A settings file Claude Code discards whole for a type error is still read
// here, as every rule that reports a dangerous value does (#595): an error in
// our bundled schema must not silence it.
func (r *cfg110) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil || len(t.Settings.Env) == 0 {
		return nil
	}
	env := t.Settings.Env
	var findings []finding.Finding
	for _, hit := range codeExecEnvHits(env, true) {
		value := strings.TrimSpace(env[hit.Key])
		f := finding.Finding{
			RuleID:   "CFG110",
			Severity: finding.Error,
			Scope:    t.Scope,
			File:     t.SettingsFile,
			Message: "env sets " + hit.Key + ": " + hit.Mechanism +
				", and Claude Code applies this block to every hook and Bash tool call, so the value runs attacker-controlled code on the next command; remove it" +
				userScopeNote(t),
		}
		upper := strings.ToUpper(hit.Key)
		switch {
		case startupFileVars[upper] && !hasRepoRelativeEntry(value):
			f.Severity = finding.Info
			f.Message = "env sets " + hit.Key + " to " + quoteValue(value) + ": " + hit.Mechanism +
				", in every hook and Bash tool call. The path is absolute or home-relative, so it names a file on the machine rather than one in the repository; on any other machine it is that machine's file or nothing" +
				userScopeNote(t)
		case gitConfigKeyVarRe.MatchString(hit.Key) && credentialHelperKeyRe.MatchString(value):
			f.Severity = finding.Warn
			f.Message = "env sets " + hit.Key + " to " + value + " with a command as its value: git runs it whenever it needs credentials for that host and hands it the request, so the repository chooses what receives them. Committed helpers like this usually wire a CI or devcontainer token; check that the command is the one intended" +
				userScopeNote(t)
		}
		findings = append(findings, f)
	}

	if v := strings.TrimSpace(env[shellPrefixVar]); v != "" {
		f := finding.Finding{
			RuleID:   "CFG110",
			Severity: finding.Error,
			Scope:    t.Scope,
			File:     t.SettingsFile,
			Message: "env sets " + shellPrefixVar + " to " + quoteValue(v) +
				": Claude Code runs every hook and Bash tool command through this program, handing it the whole command line, so whatever it names runs before and around each command; remove it",
		}
		// A prefix in the user's own settings is a choice they made for their
		// machine, typically a logging wrapper; it is listed, not alarmed on.
		if t.Scope == finding.ScopeUser {
			f.Severity = finding.Info
			f.Message = "env sets " + shellPrefixVar + " to " + quoteValue(v) +
				": every hook and Bash tool command in every project runs through this program" + userScopeNote(t)
		}
		findings = append(findings, f)
	}
	return findings
}

// startupFileVars are the variables whose value names a file or library to
// load. Real settings point them at the author's own machine as often as at the
// repository: of the 63 committed settings files with an env block measured for
// this rule, eight set BASH_ENV or ZDOTDIR, and all eight named an absolute or
// home path (a dotfiles profile, asdf.sh, a devcontainer script). The
// repository controls the content only when an entry is relative, which resolves
// against the project directory Claude Code runs hooks and tools in.
var startupFileVars = map[string]bool{
	"BASH_ENV":              true,
	"ZDOTDIR":               true,
	"PYTHONSTARTUP":         true,
	"LD_PRELOAD":            true,
	"LD_AUDIT":              true,
	"DYLD_INSERT_LIBRARIES": true,
	"DOTNET_STARTUP_HOOKS":  true,
}

var (
	credentialHelperKeyRe = regexp.MustCompile(`(?i)^credential\.(.+\.)?helper$`)
	windowsAbsRe          = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
)

// hasRepoRelativeEntry reports whether any entry of a file or library list is a
// relative path. "$PWD/x" counts as relative and "$HOME/x" does not: bash
// subjects BASH_ENV to parameter expansion before reading it, so for the one
// variable where a reference is likely, it resolves the way it reads. Entries are separated by whitespace, ";" or ":" (LD_PRELOAD
// takes either of the first and third, DOTNET_STARTUP_HOOKS the platform's path
// separator); a Windows drive path counts as absolute.
func hasRepoRelativeEntry(v string) bool {
	for _, field := range strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ' ' || r == '\t' }) {
		if windowsAbsRe.MatchString(field) {
			continue
		}
		for _, e := range strings.Split(field, ":") {
			e = strings.TrimSpace(e)
			if e == "" || strings.HasPrefix(e, "/") || strings.HasPrefix(e, "~") || strings.HasPrefix(e, "$HOME") {
				continue
			}
			return true
		}
	}
	return false
}

// quoteValue renders an env value for a message, shortened so a long wrapper
// command does not swamp the line.
func quoteValue(v string) string {
	if r := []rune(v); len(r) > 80 {
		v = string(r[:77]) + "..."
	}
	return "\"" + v + "\""
}
