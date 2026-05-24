package rules

import (
	"regexp"
	"strings"
)

// toolPatternRe extracts the pattern from a permission entry like Read(**/.env).
var toolPatternRe = regexp.MustCompile(`^[A-Za-z]+\((.*)\)$`)

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
