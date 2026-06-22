package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/version"
)

// toolPatternRe extracts the pattern from a permission entry like Read(**/.env).
var toolPatternRe = regexp.MustCompile(`^[A-Za-z]+\((.*)\)$`)

// denyAllGlobMinVersion is the Claude Code release that gave the deny tool-name
// position glob support: a bare "*" entry denies every tool. Before it, "*" is an
// unknown tool name and a no-op (denies nothing), so the deny-all suppression must
// be gated on this version.
var denyAllGlobMinVersion = version.Version{Major: 2, Minor: 1, Patch: 166}

// readAllPatterns are Read-tool deny patterns whose path glob matches every read,
// so the entry blocks all read-based access regardless of file class. These are
// version-independent: Read(...) path globs have always been honoured.
var readAllPatterns = map[string]bool{"*": true, "**": true, "**/*": true}

// denyCoversEverything reports whether the deny block contains an entry that
// blocks every read relevant to the file-class coverage rules (CFG041–044), so
// those rules must not report a per-class gap:
//   - a Read-all wildcard — Read(*) / Read(**) / Read(**/*) — on any version, or
//   - the bare "*" deny-all-tools glob — only on Claude Code >= 2.1.166, or when
//     the version is unknown (ver == nil); on older releases "*" denies nothing.
func denyCoversEverything(deny []string, ver *version.Version) bool {
	denyAllActive := ver == nil || ver.AtLeast(denyAllGlobMinVersion)
	for _, e := range deny {
		t := strings.TrimSpace(e)
		if t == "*" {
			if denyAllActive {
				return true
			}
			continue
		}
		if m := toolPatternRe.FindStringSubmatch(t); m != nil {
			tool := t[:strings.IndexByte(t, '(')]
			if strings.EqualFold(tool, "Read") && readAllPatterns[m[1]] {
				return true
			}
		}
	}
	return false
}

// denyPattern returns the path/command pattern inside a permission entry,
// stripping the Tool(...) wrapper (e.g. "Read(**/.env)" → "**/.env"). A bare
// entry is returned unchanged.
func denyPattern(entry string) string {
	e := strings.TrimSpace(entry)
	if m := toolPatternRe.FindStringSubmatch(e); m != nil {
		return m[1]
	}
	return e
}

// denyCoversAny reports whether any deny entry's pattern matches re — used by the
// deny-coverage rules (CFG041…) to check that a sensitive file class is blocked.
// A Tool(param:value) entry naming the tool's canonicalized field is skipped: the
// 2.1.178 param grammar ignores those forms (see ignoresParamForm), so they grant
// no coverage even though the value substring would otherwise match re.
func denyCoversAny(deny []string, re *regexp.Regexp) bool {
	for _, e := range deny {
		if ignoresParamForm(e) {
			continue
		}
		if re.MatchString(denyPattern(e)) {
			return true
		}
	}
	return false
}

// canonicalizedParamFields maps a tool (lower-cased) to the one input parameter
// Claude Code matches with its own canonicalizing rules and therefore IGNORES in
// the generic Tool(param:value) form — emitting a startup warning rather than
// enforcing it. A deny/ask rule written that way (e.g. Read(file_path:.env)) is a
// no-op, so cfgaudit must not count it as coverage. The fix uses Bash(rm *),
// Read(./path), WebFetch(domain:host), etc. instead.
// Source: code.claude.com/docs/en/permissions — "Match by input parameter".
var canonicalizedParamFields = map[string]string{
	"bash":         "command",
	"powershell":   "command",
	"read":         "file_path",
	"edit":         "file_path",
	"write":        "file_path",
	"grep":         "path",
	"glob":         "path",
	"notebookedit": "notebook_path",
	"webfetch":     "url",
}

// ignoresParamForm reports whether entry is a Tool(param:value) rule whose param
// is the tool's canonicalized field — a form Claude Code ignores (so it provides
// no deny coverage). Tools' own specifiers (Read(.env), WebFetch(domain:x)) and
// non-canonicalized params (Agent(model:opus)) are not matched.
func ignoresParamForm(entry string) bool {
	e := strings.TrimSpace(entry)
	open := strings.IndexByte(e, '(')
	if open < 0 || !strings.HasSuffix(e, ")") {
		return false
	}
	field, ok := canonicalizedParamFields[strings.ToLower(strings.TrimSpace(e[:open]))]
	if !ok {
		return false
	}
	inner := e[open+1 : len(e)-1]
	colon := strings.IndexByte(inner, ':')
	if colon < 0 {
		return false
	}
	// "Whitespace around the colon is ignored."
	return strings.EqualFold(strings.TrimSpace(inner[:colon]), field)
}
