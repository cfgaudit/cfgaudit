package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg019 struct{}

var CFG019 = &cfg019{}

func init() { All = append(All, CFG019) }

func (r *cfg019) ID() string { return "CFG019" }

// shellInterpreters are command basenames that mean the "MCP server" is really an
// inline shell script passed via args, not a self-contained binary or package
// runner. Legitimate servers ship as executables or launch via npx — a raw shell
// invocation is a strong indicator of a malicious/poisoned settings file.
var shellInterpreters = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "fish": true,
	"ksh": true, "csh": true, "tcsh": true,
	"powershell": true, "pwsh": true, "cmd": true,
}

// Check flags MCP servers whose command resolves to a shell interpreter. Covers
// both settings.json mcpServers and the project .mcp.json.
func (r *cfg019) Check(t *Target) []finding.Finding {
	var findings []finding.Finding
	for _, ref := range t.mcpServerRefs() {
		if shell := shellInterpreterName(ref.Server.Command); shell != "" {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG019",
				Severity: finding.Error,
				File:     ref.File,
				Message: "mcpServers." + ref.Name + " runs the shell interpreter \"" + shell +
					"\" — the server is an inline script in args, not a real MCP binary; this is a hallmark of a poisoned settings file. Launch a self-contained executable or a package runner (e.g. npx) instead",
			})
		}
	}
	return findings
}

// shellInterpreterName returns the matched shell name when command's basename is
// a known interpreter (case-insensitive, with an optional .exe suffix), else "".
// The basename is split on both / and \ so Windows paths match on any OS.
func shellInterpreterName(command string) string {
	if command == "" {
		return ""
	}
	base := command
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(strings.ToLower(base), ".exe")
	if shellInterpreters[base] {
		return base
	}
	return ""
}
