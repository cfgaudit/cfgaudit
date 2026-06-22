package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg076 struct{}

var CFG076 = &cfg076{}

func init() { All = append(All, CFG076) }

func (r *cfg076) ID() string { return "CFG076" }

// driveRootRe matches a bare Windows drive root: C:, C:\, C:/, D:\, …
var driveRootRe = regexp.MustCompile(`^[A-Za-z]:[\\/]?$`)

// mcpBroadRoot reports whether a path argument exposes a broad filesystem root,
// and whether it is a (relative) parent-traversal form. It mirrors CFG061's
// isBroadSandboxPath, extended with Windows drive roots and trailing-slash home
// forms — an MCP filesystem server handed one of these can reach the whole
// machine or home directory.
func mcpBroadRoot(p string) (broad, traversal bool) {
	switch strings.TrimSpace(p) {
	case "/", "~", "~/", "$HOME", "${HOME}", "$HOME/", "${HOME}/", "/*", "~/*":
		return true, false
	case "..", "../":
		return true, true
	}
	p = strings.TrimSpace(p)
	if driveRootRe.MatchString(p) {
		return true, false
	}
	if strings.HasPrefix(p, "../") || strings.HasPrefix(p, "~/..") {
		return true, true
	}
	return false, false
}

// argPathValue returns the path-like value an MCP server arg carries: the arg
// itself when positional, or the value after '=' for a --flag=value form. A bare
// flag (no '=') yields "" — its value, if any, arrives as the next positional arg.
func argPathValue(a string) string {
	if strings.HasPrefix(a, "-") {
		if i := strings.IndexByte(a, '='); i >= 0 {
			return a[i+1:]
		}
		return ""
	}
	return a
}

// Check flags an MCP server whose args expose a broad filesystem root (/, ~,
// $HOME, a drive root, or a parent-traversal path) — e.g. a filesystem server
// pointed at the whole machine or home directory rather than a scoped subdir,
// granting the agent read/write far beyond what it needs. Scans every MCP server
// in mcpServerRefs (settings.json mcpServers + .mcp.json + cross-agent).
func (r *cfg076) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		for _, a := range ref.Server.Args {
			v := argPathValue(a)
			if v == "" {
				continue
			}
			broad, traversal := mcpBroadRoot(v)
			if !broad {
				continue
			}
			sev, scope := finding.Error, "the entire filesystem or home directory"
			if traversal {
				sev, scope = finding.Warn, "directories above its working directory"
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG076",
				Severity: sev,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + " exposes \"" + strings.TrimSpace(v) +
					"\" as a filesystem path — the server can read and write " + scope +
					"; scope it to the narrowest directory it needs" + userScopeNote(t),
			})
		}
	}
	return findings
}
