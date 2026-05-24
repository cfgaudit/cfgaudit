package rules

import (
	"regexp"

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
	{regexp.MustCompile(`(?:curl|wget)\s+[^\n|;&]*\|\s*(?:bash|sh|zsh|python3?|node|perl)\b`), "curl/wget piped into a shell or interpreter"},
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

func (r *cfg014) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}

	var findings []finding.Finding
	for _, site := range commandSites(t.Settings) {
		for _, p := range downloadExecPatterns {
			if !p.re.MatchString(site.Command) {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG014",
				Severity: finding.Error,
				File:     t.SettingsFile,
				Message:  site.Label + " downloads and executes remote code (" + p.label + ") — this runs unverified remote code every time it runs; download to a file first and verify a checksum before running" + userScopeNote(t),
			})
			break
		}
	}
	return findings
}
