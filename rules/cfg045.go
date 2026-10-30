// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

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
		if ShellcheckError() != nil {
			return findings // one failure is enough; don't wait out a timeout per site
		}
		out, err := runShellcheck(site.Command, t.ShellCheckExclude)
		if err != nil {
			recordShellcheckError(err)
			continue
		}
		comments, err := parseShellcheck(out)
		if err != nil {
			recordShellcheckError(err)
			continue
		}
		for _, c := range comments {
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

// shellcheckTimeout bounds one shellcheck call, so a hanging binary on PATH
// cannot hang the scan (#1062). A variable so tests can shorten it.
var shellcheckTimeout = 10 * time.Second

// shellcheckFailure holds the first failed shellcheck run of the process. Rules
// return only findings, so the CLI reads the failure through ShellcheckError
// and exits 2 instead of reporting a scan whose shell analysis did not run.
var shellcheckFailure struct {
	sync.Mutex
	err error
}

func recordShellcheckError(err error) {
	shellcheckFailure.Lock()
	defer shellcheckFailure.Unlock()
	if shellcheckFailure.err == nil {
		shellcheckFailure.err = err
	}
}

// ShellcheckError returns the first shellcheck failure since the last
// ResetShellcheckError, or nil.
func ShellcheckError() error {
	shellcheckFailure.Lock()
	defer shellcheckFailure.Unlock()
	return shellcheckFailure.err
}

// ResetShellcheckError clears the recorded failure before a new scan.
func ResetShellcheckError() {
	shellcheckFailure.Lock()
	defer shellcheckFailure.Unlock()
	shellcheckFailure.err = nil
}

// runShellcheck pipes a hook command (wrapped as a bash script) to
// `shellcheck --format=json -` and returns its JSON output. ShellCheck exits 1
// when it reports findings, which is not an execution error; 2 and above mean
// it could not check the script (bad options, unsupported shell).
func runShellcheck(command string, exclude []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shellcheckTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "shellcheck", shellcheckArgs(exclude)...) // #nosec G204 -- fixed argv plus validated SC codes; the command is fed via stdin, not the shell
	cmd.Stdin = strings.NewReader("#!/bin/bash\n" + command + "\n")
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("shellcheck did not finish within %s", shellcheckTimeout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() == 1 {
			return out, nil // findings present
		}
		return nil, fmt.Errorf("shellcheck failed (exit %d): %s", exitErr.ExitCode(), firstLine(exitErr.Stderr))
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func firstLine(b []byte) string {
	line, _, _ := bytes.Cut(bytes.TrimSpace(b), []byte("\n"))
	if len(line) == 0 {
		return "no error output"
	}
	return string(line)
}

// shellcheckArgs is the shellcheck argv for one command site. exclude holds
// codes already normalized to "SC2086" by the config loader.
func shellcheckArgs(exclude []string) []string {
	args := []string{"--shell=bash", "--format=json"}
	if len(exclude) > 0 {
		args = append(args, "--exclude="+strings.Join(exclude, ","))
	}
	return append(args, "-")
}

func parseShellcheck(out []byte) ([]scComment, error) {
	var comments []scComment
	if err := json.Unmarshal(out, &comments); err != nil {
		return nil, fmt.Errorf("shellcheck output is not its JSON format: %s", firstLine(out))
	}
	return comments, nil
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
