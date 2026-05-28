package rules

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg045 struct{}

var CFG045 = &cfg045{}

func init() { All = append(All, CFG045) }

func (r *cfg045) ID() string { return "CFG045" }

// scComment is one ShellCheck JSON diagnostic.
type scComment struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Level   string `json:"level"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Check runs ShellCheck over each command site (hooks + helpers) and surfaces its
// diagnostics. Opt-in: only runs when t.ShellCheck is set (CLI --shellcheck /
// config, gated on the binary being available). ShellCheck understands shell
// grammar, so it catches quoting/eval/pipe issues that regex rules miss.
func (r *cfg045) Check(t *Target) []finding.Finding {
	if t == nil || !t.ShellCheck {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSites(t) {
		out, err := runShellcheck(site.Command)
		if err != nil {
			continue // exec error (e.g. binary vanished) — gated/handled by the CLI
		}
		for _, c := range parseShellcheck(out) {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG045",
				Severity: scSeverity(c.Level),
				File:     site.File,
				Message: fmt.Sprintf("%s — shellcheck SC%d (%s): %s", site.Label, c.Code, c.Level, c.Message) +
					userScopeNote(t),
			})
		}
	}
	return findings
}

// runShellcheck pipes a hook command (wrapped as a bash script) to
// `shellcheck --format=json -` and returns its JSON output. ShellCheck exits
// non-zero when it reports findings, which is not an execution error.
func runShellcheck(command string) ([]byte, error) {
	cmd := exec.Command("shellcheck", "--shell=bash", "--format=json", "-") // #nosec G204 -- fixed argv; the command is fed via stdin, not the shell
	cmd.Stdin = strings.NewReader("#!/bin/bash\n" + command + "\n")
	out, err := cmd.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return out, nil // non-zero exit = findings present
		}
		return nil, err
	}
	return out, nil
}

func parseShellcheck(out []byte) []scComment {
	var comments []scComment
	if err := json.Unmarshal(out, &comments); err != nil {
		return nil
	}
	return comments
}

func scSeverity(level string) finding.Severity {
	switch strings.ToLower(level) {
	case "error":
		return finding.Error
	case "warning":
		return finding.Warn
	default: // info, style
		return finding.Info
	}
}

// ShellcheckAvailable reports whether the shellcheck binary is on PATH.
func ShellcheckAvailable() bool {
	_, err := exec.LookPath("shellcheck")
	return err == nil
}
