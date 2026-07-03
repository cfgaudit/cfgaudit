package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg077 struct{}

var CFG077 = &cfg077{}

func init() { All = append(All, CFG077) }

func (r *cfg077) ID() string { return "CFG077" }

// antiForensicsPatterns match commands that destroy an audit trail — wiping
// shell history, purging system logs, or shredding files. A hook that runs a
// payload and then clears the trace is "covering tracks": the cleanup is the
// tell even when the payload itself is obfuscated. Distinct from CFG039
// (a broad `rm -rf`) and CFG027 (persistence) — these commands delete evidence.
// Each regex is scoped to a destructive verb acting on a log/history target so a
// bare read (`journalctl -u foo`, `cat ~/.bash_history`) does not match.
var antiForensicsPatterns = []struct {
	re    *regexp.Regexp
	label string
}{
	// Shell history.
	{regexp.MustCompile(`(?i)\bhistory\s+-[a-z]*c`), "clears shell history (history -c)"},
	{regexp.MustCompile(`(?i)\bunset\s+HISTFILE\b`), "disables shell history (unset HISTFILE)"},
	{regexp.MustCompile(`(?i)\bHISTFILE\s*=\s*/dev/null\b`), "redirects shell history to /dev/null (HISTFILE=/dev/null)"},
	{regexp.MustCompile(`(?i)\bset\s+\+o\s+history\b`), "disables shell history logging (set +o history)"},
	{regexp.MustCompile(`(?i)(?:>|\brm\b|\btruncate\b|\bshred\b)[^|;&\n]*\.(?:bash|zsh)_history\b`), "deletes or truncates the shell history file"},
	// System / audit logs.
	{regexp.MustCompile(`(?i)\bjournalctl\b[^|;&\n]*--(?:vacuum|rotate)`), "purges the systemd journal (journalctl --vacuum/--rotate)"},
	{regexp.MustCompile(`(?i)(?:\brm\b|\btruncate\b|\bshred\b|\bdd\b)[^|;&\n]*/var/log\b`), "deletes or truncates system logs (/var/log)"},
	{regexp.MustCompile(`(?i)(?:>|\brm\b|\btruncate\b|\bshred\b)[^|;&\n]*\b(?:wtmp|btmp|lastlog)\b`), "clears login/audit logs (wtmp/btmp/lastlog)"},
	// Secure file wiping (anti-recovery).
	{regexp.MustCompile(`(?i)\b(?:shred|srm)\b`), "shreds files to prevent recovery (shred/srm)"},
}

// Check flags command sites whose command destroys an audit trail — clearing
// shell history, purging system logs, or shredding files. One finding per site
// (the first matching category). Scans hooks and command-running helpers.
func (r *cfg077) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSites(t) {
		for _, p := range antiForensicsPatterns {
			if !p.re.MatchString(site.Command) {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "CFG077",
				Severity: finding.Error,
				File:     site.File,
				Message: site.Label + " destroys an audit trail — it " + p.label +
					". A hook has no legitimate reason to wipe history or logs; this is anti-forensics that hides another malicious action. Remove it" + userScopeNote(t),
			})
			break
		}
	}
	return findings
}
