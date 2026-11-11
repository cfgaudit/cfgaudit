// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg014 struct{}

var CFG014 = &cfg014{}

func init() { All = append(All, CFG014) }

func (r *cfg014) ID() string { return "CFG014" }

// downloadExecPatterns match "fetch remote code and run it" one-liners, on Unix
// shells and on Windows/PowerShell. Each carries a short label for the message.
var downloadExecPatterns = []struct {
	re    *regexp.Regexp
	label string
}{
	// Unix: curl/wget piped into a shell or interpreter. The char class forbids
	// \n | ; & between the downloader and the pipe so only true pipelines match.
	// The interpreter's own arguments are checked in pipesProgramToStdin.
	{curlPipeInterpreterRe, "curl/wget piped into a shell or interpreter"},
	// PowerShell: a downloader (iwr/Invoke-WebRequest/Invoke-RestMethod/curl/wget)
	// piped into Invoke-Expression/IEX.
	{regexp.MustCompile(`(?i)(?:iwr|invoke-webrequest|invoke-restmethod|curl|wget)\b[^\n|;&]*\|\s*(?:iex|invoke-expression)\b`), "PowerShell download piped into IEX"},
	// PowerShell: IEX over a WebClient DownloadString, in either order.
	{regexp.MustCompile(`(?i)(?:iex|invoke-expression)\b[^\n]{0,120}\.DownloadString\s*\(`), "PowerShell IEX(...DownloadString())"},
	{regexp.MustCompile(`(?i)\.DownloadString\s*\([^\n]{0,120}\|\s*(?:iex|invoke-expression)\b`), "PowerShell DownloadString piped into IEX"},
	// Windows LOLBins that download a remote file.
	{regexp.MustCompile(`(?i)\bcertutil(?:\.exe)?\b[^\n]*-urlcache\b`), "certutil -urlcache download"},
	{regexp.MustCompile(`(?i)\bbitsadmin(?:\.exe)?\b[^\n]*/transfer\b`), "bitsadmin /transfer download"},
}

var curlPipeInterpreterRe = regexp.MustCompile(`(?:curl|wget)\s+[^\n|;&]*\|\s*(bash|sh|zsh|python3?|node|perl)\b([^\n|;&]*)`)

// pipesProgramToStdin reports whether some curl/wget pipe in command hands
// the download to an interpreter as its program. With inline code (`python3
// -c`, `node -e`, `python3 -m json.tool`) or a script file operand, the
// interpreter reads the download as data, which is how a script parses JSON
// (#1355).
func pipesProgramToStdin(command string) bool {
	for _, m := range curlPipeInterpreterRe.FindAllStringSubmatch(command, -1) {
		if !interpreterTakesProgram(m[1], m[2]) {
			return true
		}
	}
	return false
}

// interpreterTakesProgram reports whether the arguments after interp give it
// its program: an inline-code flag or a script file. Redirections are not
// operands, and the arguments end at a closing parenthesis, backtick, comment
// or quote, as in `$(curl … | python3)` and `bash -c "curl … | bash"`.
func interpreterTakesProgram(interp, rest string) bool {
	if i := strings.IndexAny(rest, ")`#"); i >= 0 {
		rest = rest[:i]
	}
	shell := interp == "bash" || interp == "sh" || interp == "zsh"
	for _, arg := range strings.Fields(rest) {
		switch {
		case strings.Trim(arg, `"'`) == "":
			return false
		case arg == "-" || arg == "--":
			return false
		case strings.ContainsAny(arg[:1], "<>0123456789") && strings.ContainsAny(arg, "<>"):
			continue
		case arg == "--eval" || arg == "--print" || strings.HasPrefix(arg, "--eval=") || strings.HasPrefix(arg, "--print="):
			return interp == "node"
		case strings.HasPrefix(arg, "--"):
			continue
		case strings.HasPrefix(arg, "-"):
			flags := arg[1:]
			switch {
			case shell && strings.Contains(flags, "s"):
				return false
			case shell && strings.Contains(flags, "c"),
				strings.HasPrefix(interp, "python") && strings.ContainsAny(flags, "cm"),
				interp == "node" && strings.ContainsAny(flags, "ep"),
				interp == "perl" && strings.ContainsAny(flags, "eE"):
				return true
			}
		default:
			return true
		}
	}
	return false
}

func (r *cfg014) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}

	var findings []finding.Finding
	sites := commandSitesWithScripts(t)
	for i, site := range sites {
		reported := false
		for _, p := range downloadExecPatterns {
			if !p.re.MatchString(site.Command) {
				continue
			}
			if p.re == curlPipeInterpreterRe && !pipesProgramToStdin(site.Command) {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG014",
				Severity: finding.Error,
				File:     site.File,
				Line:     site.Line,
				Message:  site.Label + " downloads and executes remote code (" + p.label + ") — this runs unverified remote code every time it runs; download to a file first and verify a checksum before running" + userScopeNote(t),
			})
			reported = true
			break
		}
		if reported {
			continue
		}
		// #1686: a download saved to a file and run by a later step, on the same
		// command line or on the next line of the same script.
		runs := downloadThenRuns(site.Command)
		if !runs && i+1 < len(sites) && sites[i+1].File == site.File && sites[i+1].Label == site.Label && sites[i+1].Line == site.Line+1 {
			runs = downloadThenRuns(site.Command + "\n" + sites[i+1].Command)
		}
		if runs {
			findings = append(findings, finding.Finding{
				RuleID:   "CFG014",
				Severity: finding.Error,
				File:     site.File,
				Line:     site.Line,
				Message:  site.Label + " downloads and executes remote code (download saved to a file and then run) — this runs unverified remote code every time it runs; verify a checksum of the file before running it" + userScopeNote(t),
			})
		}
	}
	return findings
}
