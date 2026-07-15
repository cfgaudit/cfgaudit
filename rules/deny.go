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

// readDenyPattern returns the path glob of a Read(...) deny entry and true, or
// ("", false) for any other entry. The deny-coverage rules (CFG041–044) ask
// whether Claude can *read* a sensitive file class, and only a Read deny stops the
// Read tool:
//   - A Read deny also blocks the Edit tool on the same path (>= 2.1.208), but a
//     Write / NotebookEdit / Glob / Grep / Edit deny does not block Read.
//   - Claude Code ignores the Write(<glob>) / Glob(<glob>) / NotebookEdit(<glob>)
//     specifier forms outright (startup warning, >= 2.1.210 — "use Edit(path) or
//     Read(path) instead"), so they grant nothing at all.
//   - The Read(param:value) form on the canonicalized file_path field is likewise
//     ignored (see ignoresParamForm), so it yields no coverage even though the
//     value substring would otherwise match.
//
// Deny-all wildcards (Read(**), the bare "*") are handled by denyCoversEverything,
// which each caller checks first. Source: code.claude.com/docs/en/permissions.
func readDenyPattern(entry string) (string, bool) {
	e := strings.TrimSpace(entry)
	if ignoresParamForm(e) {
		return "", false
	}
	m := toolPatternRe.FindStringSubmatch(e)
	if m == nil {
		return "", false // bare tool name or non-permission entry — no path glob
	}
	if tool := e[:strings.IndexByte(e, '(')]; !strings.EqualFold(strings.TrimSpace(tool), "Read") {
		return "", false
	}
	return m[1], true
}

// denyCoversAny reports whether any Read deny entry's path glob matches re — used
// by the deny-coverage rules (CFG041…) to check that a sensitive file class is
// blocked from being read. Non-Read deny entries provide no read coverage (see
// readDenyPattern).
func denyCoversAny(deny []string, re *regexp.Regexp) bool {
	for _, e := range deny {
		if pat, ok := readDenyPattern(e); ok && re.MatchString(pat) {
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
