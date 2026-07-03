package rules

import (
	"regexp"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg078 struct{}

var CFG078 = &cfg078{}

func init() { All = append(All, CFG078) }

func (r *cfg078) ID() string { return "CFG078" }

var (
	// credStoreCmdRe matches a CLI that directly reads an OS credential store —
	// the invocation itself dumps secrets, so no separate read verb is needed.
	//   - macOS Keychain: `security find-generic-password` / `find-internet-password`
	//     / `dump-keychain` / `export`
	//   - Linux Secret Service: `secret-tool lookup` / `search`
	//   - system password DB: `getent shadow` / `gshadow`
	credStoreCmdRe = regexp.MustCompile(`(?i)\bsecurity\s+(?:find-(?:generic|internet)-password|dump-keychain|export)\b|\bsecret-tool\s+(?:lookup|search)\b|\bgetent\s+g?shadow\b`)
	// credFileRe matches a read/copy/archive verb touching a credential store on
	// disk: the shadow password DB, the macOS Keychain directory, the Linux
	// keyring directory, or a browser saved-credential DB (Firefox logins.json /
	// key4.db, Chromium "Login Data"). The verb list mirrors CFG037.
	credFileRe = regexp.MustCompile(`(?i)\b(?:cat|cp|scp|rsync|tar|mv|base64|xxd|dd|less|more|head|tail|install|gzip|zip|openssl|strings|sqlite3|sqlcipher)\b[^|;&\n]*(?:/etc/g?shadow\b|Library/Keychains\b|\.local/share/keyrings\b|\blogins\.json\b|\bkey4\.db\b|Login[\\ ]+Data)`)
)

// Check flags command sites that read an OS credential store or the system
// password database — macOS Keychain, Linux Secret Service / keyring,
// /etc/shadow, or a browser's saved-credential DB. These are the highest-value
// secret stores on a developer machine; a hook has no legitimate reason to read
// them, so (like CFG037 for SSH keys) the read itself is flagged regardless of
// destination. Scans hooks and command-running helpers.
func (r *cfg078) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSites(t) {
		if !credStoreCmdRe.MatchString(site.Command) && !credFileRe.MatchString(site.Command) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG078",
			Severity: finding.Error,
			File:     site.File,
			Message: site.Label + " reads an OS credential store (macOS Keychain, Linux keyring, /etc/shadow, or a browser saved-password DB) — this exfiltrates stored passwords and tokens. A hook must not read credential stores" +
				userScopeNote(t),
		})
	}
	return findings
}
