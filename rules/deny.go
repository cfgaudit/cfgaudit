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

// denyReadsCovered reports whether the deny block denies READING the file class
// described by classRe (matched against deny path globs) and samples
// (representative secret paths of the class), for the file-class coverage rules
// (CFG041–044). It is evaluated in order and honours the exception form (#581):
//
//   - grant: a bare "*" deny-all-tools glob (>= 2.1.166, or unknown version), a
//     Read-all wildcard Read(*) / Read(**) / Read(**/*) on any version, or a Read
//     deny whose path glob matches classRe.
//   - carve: an exception rule — any Tool(!glob), with an optional ./ before the
//     "!" — removes, from the rules listed before it, coverage of the paths its
//     glob matches. It carves this class when its glob matches a sample path.
//
// The carve is matched by glob against real secret paths rather than by classRe
// against the exception's glob string, so a narrow re-allow such as
// Read(!**/.env.example) does not read as exposing .env, while Read(!**/.env)
// does. Any tool wrapper counts for the carve: the "!" form denies nothing, and
// treating it uniformly errs toward reporting (the managed-settings filter names
// Read and Edit, but a Write(!glob) deny already grants nothing here).
func denyReadsCovered(deny []string, classRe *regexp.Regexp, samples []string, ver *version.Version) bool {
	denyAllActive := ver == nil || ver.AtLeast(denyAllGlobMinVersion)
	covered := false
	for _, e := range deny {
		if g, ok := exceptionGlob(e); ok {
			if matchesAnySample(g, samples) {
				covered = false
			}
			continue
		}
		t := strings.TrimSpace(e)
		if t == "*" {
			if denyAllActive {
				covered = true
			}
			continue
		}
		if pat, ok := readDenyPattern(e); ok {
			if readAllPatterns[pat] || classRe.MatchString(pat) {
				covered = true
			}
		}
	}
	return covered
}

// exceptionGlob returns the glob of a Tool(!glob) / Tool(./!glob) exception rule
// and true, or ("", false) for any other entry. The binary recognises the form
// with /^(?:Read|Edit)\((?:\.\/)?!/ (2.1.269+); cfgaudit accepts the "!" under
// any tool name, since the deny side already grants nothing for the tools the
// binary excludes.
func exceptionGlob(entry string) (string, bool) {
	m := toolPatternRe.FindStringSubmatch(strings.TrimSpace(entry))
	if m == nil {
		return "", false
	}
	inner := strings.TrimSpace(m[1])
	inner = strings.TrimPrefix(inner, "./")
	if rest, ok := strings.CutPrefix(inner, "!"); ok {
		return strings.TrimSpace(rest), true
	}
	return "", false
}

// matchesAnySample reports whether the glob matches any of the class's
// representative secret paths. A read-all glob (**, */**, …) matches every
// sample and so carves every class.
func matchesAnySample(glob string, samples []string) bool {
	if glob == "" {
		return false
	}
	re := globToPathRegexp(glob)
	for _, s := range samples {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// globToPathRegexp compiles a permission-rule path glob to a regexp: `**` spans
// path segments (including none, so `**/.env` matches `.env`), `*` stays within a
// segment, `?` is one non-separator character, and a leading `//` (filesystem
// root anchor) or `/` is treated literally. Used only to test an exception glob
// against a handful of sample paths, so per-call compilation is fine.
func globToPathRegexp(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		switch glob[i] {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				b.WriteString(".*")
				i++
				if i+1 < len(glob) && glob[i+1] == '/' {
					i++
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(glob[i])))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
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
