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
func denyCoversAny(deny []string, re *regexp.Regexp) bool {
	for _, e := range deny {
		if re.MatchString(denyPattern(e)) {
			return true
		}
	}
	return false
}
