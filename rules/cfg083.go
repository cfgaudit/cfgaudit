package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg083 struct{}

var CFG083 = &cfg083{}

func init() { All = append(All, CFG083) }

func (r *cfg083) ID() string { return "CFG083" }

// chromiumCmdFlags are the Chromium switches that replace the binary the browser
// executes for a child process. A browser-automation MCP server (Playwright,
// Puppeteer, browser-use, crawlers) passes launch switches straight through from
// its args, so one of these in a committed config runs an arbitrary program the
// moment the browser starts — no injection required, because the attacker wrote
// the config.
//
// CVE-2026-57572 (CVSS 10.0, CWE-88) is the class exemplar: Crawl4AI let
// unvalidated browser arguments reach Chromium's launch parameters, yielding
// arbitrary command execution. That CVE is a *server-side* argument-injection
// bug; it is cited because it proves this switch class executes commands in
// practice, not because the CVE is about MCP configuration.
var chromiumCmdFlags = []string{
	"--utility-cmd-prefix",
	"--renderer-cmd-prefix",
	"--gpu-launcher",
	"--browser-subprocess-path",
}

// debuggerPrefixRe matches the legitimate use of a command-prefix switch: running
// a child process under a debugger or profiler. Optionally path-qualified
// (/usr/bin/gdb) and tolerant of trailing arguments.
var debuggerPrefixRe = regexp.MustCompile(`(?i)^(?:[\w./-]*/)?(?:gdb|lldb|valgrind|strace|ltrace|perf|rr|heaptrack|catchsegv|xvfb-run)\b`)

// noZygoteRe marks the switch that forces Chromium to fork/exec each child
// through the replaced command instead of the pre-forked zygote. Harmless alone,
// so it never produces a finding by itself — it only makes a command-replacing
// switch reliable, which the message notes when both appear.
var noZygoteRe = regexp.MustCompile(`^--no-zygote\b`)

// Check flags MCP servers whose args carry a Chromium command-replacing launch
// switch. Runs over every MCP surface mcpServerRefs() covers. Debugger and
// profiler prefixes, empty values and $VAR templates are not flagged.
func (r *cfg083) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding

	for _, ref := range t.mcpServerRefs() {
		args := ref.Server.Args
		hasNoZygote := false
		for _, a := range args {
			if noZygoteRe.MatchString(strings.TrimSpace(a)) {
				hasNoZygote = true
				break
			}
		}

		for i := range args {
			flag, value, ok := chromiumCmdFlagValue(args, i)
			if !ok {
				continue
			}
			if value == "" || isSecretReference(value) || debuggerPrefixRe.MatchString(value) {
				continue
			}
			tail := ""
			if hasNoZygote {
				tail = " It is paired with --no-zygote, which forces every child process through that command rather than the pre-forked zygote, making the substitution reliable."
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG083",
				Severity: finding.Error,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + ".args passes " + flag + "=" + value +
					" — this Chromium switch replaces the binary the browser executes for a child process, so launching the browser runs \"" + value +
					"\" instead." + tail + " A repo-controlled config has no legitimate reason to redirect Chromium's child processes; remove it" + userScopeNote(t),
			})
		}
	}
	return findings
}

// chromiumCmdFlagValue reports whether args[i] is a command-replacing Chromium
// switch and returns the flag and its value. Both spellings are handled:
// --flag=value, and --flag followed by the value as the next argument.
func chromiumCmdFlagValue(args []string, i int) (flag, value string, ok bool) {
	tok := strings.TrimSpace(args[i])
	for _, f := range chromiumCmdFlags {
		switch {
		case strings.HasPrefix(tok, f+"="):
			return f, unquoteArg(strings.TrimPrefix(tok, f+"=")), true
		case tok == f:
			if i+1 < len(args) {
				return f, unquoteArg(strings.TrimSpace(args[i+1])), true
			}
			return f, "", true // dangling flag — nothing to judge
		}
	}
	return "", "", false
}

// unquoteArg strips a single layer of surrounding quotes from an arg value.
func unquoteArg(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"'`)
}
