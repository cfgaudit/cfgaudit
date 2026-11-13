// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// secretDenyRe matches a deny entry that guards secret files: the bare Read,
// Edit or Write tool, a wildcard, or a rule on a credential-like path.
//
// `token` is matched only as a credential file name or path component
// (`token`, `tokens.json`, `.token`, `access_token`, a `token/` directory),
// not as a substring of a source file name such as `tokens.h` or
// `spam-tokens.json`, which do not guard a secret (#1662).
var secretDenyRe = regexp.MustCompile(`(?i)^(?:Read|Edit|Write|Grep|Glob)(?:\(\s*(?:\*\*?|/?/?\*\*(?:/\*)?)\s*\)|\([^)]*(?:\.env|\.pem|\.key\b|\.p12|\.pfx|\.jks|\.ssh|id_(?:rsa|ed25519|ecdsa|dsa)|\.aws|gcloud|\.azure|credential|secret|\.npmrc|\.netrc|\.kube|\.gnupg|\.docker)[^)]*\)|\(\s*(?:[^)]*/)?(?:access[_-])?\.?tokens?(?:\.json)?(?:/[^)]*)?\))?$`)

// guardsSecrets reports whether any deny entry guards secret files.
func guardsSecrets(deny []string) bool {
	for _, d := range deny {
		if secretDenyRe.MatchString(strings.TrimSpace(d)) {
			return true
		}
	}
	return false
}

// credentialCoverage grades a credential-coverage gap of CFG041 to CFG044
// (#1172) and returns the severity and a clause for the message. The gap is
// an error for a deny list that guards secrets and misses this class whole,
// and in auto or bypass mode, where nothing else stops a read. It is a
// warning when the deny list guards no secret file at all, because it was
// written for something else (a git push, a generated directory): in the
// pre-release corpus run for v1.20.0, 65 of 110 files were of that kind and
// got three or four errors for adding one unrelated deny, where no deny list
// at all gets one CFG006 warning. It is also a warning when the class is
// partly covered.
// interpreterAllowRe matches an allow rule for an interpreter or a shell,
// whose code can read any path without the path showing in the command.
var interpreterAllowRe = regexp.MustCompile(`(?i)^Bash\(\s*(?:python[0-9.]*|py|node|nodejs|bun|deno|ruby|perl|php|sh|bash|zsh|dash|pwsh|powershell)\b`)

// interpreterRunsAnyCode reports whether an interpreter allow lets the agent
// run code of its own choosing, which can read any path without the path
// showing in the command (#1661). The exemptions are CFG023's: an exact
// command with no wildcard (Bash(php -v)), a version flag (Bash(node
// --version:*), #1204), a named script or a `-m` module that does not run
// other code (Bash(node scripts/check.js:*), #1205), and a shell given a
// script (Bash(bash build.sh:*), #874). Interpreters CFG023 does not list
// (php, bun, nodejs, py, python3.12) get the same reading.
func interpreterRunsAnyCode(entry string) bool {
	m := bashAllowRe.FindStringSubmatch(strings.TrimSpace(entry))
	if m == nil {
		return true
	}
	inner := strings.TrimSpace(m[1])
	if !strings.Contains(inner, "*") {
		return false
	}
	tok := strings.ToLower(strings.Fields(strings.ReplaceAll(inner, ":", " "))[0])
	switch {
	case shellInterpreters[tok]:
		return !shellScriptPinned(inner)
	case interpreterVersionFlag(tok, inner):
		return false
	}
	return !interpreterOperandPinned(inner)
}

// interpreterVersionFlag reports an interpreter entry whose first argument
// is a version flag that exits before running any code: --version, -V for
// Python, -v for the others. Python's -v is verbose mode and Ruby's -v goes
// on to run a program, so neither counts.
func interpreterVersionFlag(tok, inner string) bool {
	fields := strings.Fields(inner)
	if len(fields) < 2 {
		return false
	}
	switch flag := strings.TrimSuffix(fields[1], ":*"); {
	case flag == "--version":
		return true
	case strings.HasPrefix(tok, "py"):
		return flag == "-V"
	case tok == "ruby":
		return false
	default:
		return flag == "-v"
	}
}

// readHomeRe matches a Read allow on an absolute path that reaches the home
// directory: the whole file system or a home root (#1661). Read(//tmp/**)
// does not.
var readHomeRe = regexp.MustCompile(`^Read\(//(?:\*\*?|(?:home|Users|root)(?:/.*)?)\)$`)

func readReachesHome(entry string) bool {
	return readHomeRe.MatchString(entry)
}

// silentHomeRoute reports whether the allow list or additionalDirectories let
// the agent read a file in the home directory without asking (#1172).
// Measured on Claude Code 2.1.316: a Read of a path outside the project is
// asked about, and so is `cat` on it under an allowed Bash(cat:*), since
// Claude Code checks the path of a read-only command. A bare Read allow and
// an allowed interpreter (Bash(python3:*) with the path inside -c code) read
// it silently, and so does any command once additionalDirectories or
// --add-dir covers the directory.
func silentHomeRoute(t *Target) bool {
	p := t.Settings.Permissions
	if p == nil {
		return false
	}
	for _, a := range p.Allow {
		a = strings.TrimSpace(a)
		switch {
		case a == "Read", a == "Bash", a == "Bash(*)", interpreterAllowRe.MatchString(a) && interpreterRunsAnyCode(a):
			return true
		case strings.HasPrefix(a, "Read(") && (readReachesHome(a) || strings.HasPrefix(a, "Read(~") || a == "Read(*)" || a == "Read(**)"):
			return true
		}
	}
	for _, d := range p.AdditionalDirectories {
		switch strings.TrimRight(strings.TrimSpace(d), "/") {
		case "", "~", "$HOME", "/home", "/Users":
			return true
		}
	}
	return false
}

func credentialCoverage(t *Target, deny []string, partial bool) (finding.Severity, string) {
	return credentialCoverageAt(t, deny, partial, false)
}

// credentialCoverageAt is credentialCoverage for a class that lives in the
// home directory (CFG043, CFG044): there a gap is an error only when a silent
// route to the file exists (#1172).
func credentialCoverageAt(t *Target, deny []string, partial, home bool) (finding.Severity, string) {
	mode := ""
	if t.Settings != nil && t.Settings.Permissions != nil {
		mode = t.Settings.Permissions.DefaultMode
	}
	switch {
	case mode == "bypassPermissions" || mode == "auto":
		return finding.Error, ""
	case !guardsSecrets(deny):
		return finding.Warn, " (the deny list guards no secret file yet; it holds other rules)"
	case partial:
		return finding.Warn, " (the rest of this class is already denied)"
	case home && !silentHomeRoute(t):
		return finding.Warn, " (these files are outside the working directory, where Claude Code asks before reading them, and no allow rule or additional directory opens a silent route)"
	}
	return finding.Error, ""
}
