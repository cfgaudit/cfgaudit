package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg037 struct{}

var CFG037 = &cfg037{}

func init() { All = append(All, CFG037) }

func (r *cfg037) ID() string { return "CFG037" }

var (
	// privKeyNameRe matches an SSH private-key filename token.
	privKeyNameRe = regexp.MustCompile(`(?i)\bid_(?:rsa|ed25519|dsa|ecdsa)\b`)
	// sshAccessRe matches a read/copy/archive command that touches a .ssh path.
	sshAccessRe = regexp.MustCompile(`(?i)\b(?:cat|cp|scp|rsync|tar|mv|base64|xxd|dd|less|more|head|tail|install|gzip|zip|openssl)\b[^|;&\n]*\.ssh(?:/|\b)`)
	// sshFileRe captures the filename referenced under .ssh/.
	sshFileRe = regexp.MustCompile(`(?i)\.ssh/([\w.\-]+)`)
)

// Check flags command sites that read, copy, or archive SSH private keys —
// exfiltrating them enables lateral movement to any server the developer can
// reach. Non-key files (known_hosts, config, authorized_keys, *.pub) are not
// flagged. Covers hooks and command-running helpers.
func (r *cfg037) Check(t *Target) []finding.Finding {
	if t == nil || t.Settings == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSites(t.Settings) {
		if !sshPrivateKeyAccess(site.Command) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG037",
			Severity: finding.Error,
			File:     t.SettingsFile,
			Message:  site.Label + " reads or copies an SSH private key — exfiltrating it enables lateral movement to every server the developer can reach. A hook must not access ~/.ssh key material" + userScopeNote(t),
		})
	}
	return findings
}

func sshPrivateKeyAccess(cmd string) bool {
	// An explicit private-key filename (id_rsa, …) that is not the .pub variant.
	for _, m := range privKeyNameRe.FindAllStringIndex(cmd, -1) {
		if !strings.HasPrefix(cmd[m[1]:], ".pub") {
			return true
		}
	}
	// A read/copy/archive command touching .ssh.
	if !sshAccessRe.MatchString(cmd) {
		return false
	}
	files := sshFileRe.FindAllStringSubmatch(cmd, -1)
	if len(files) == 0 {
		return true // whole-directory access (e.g. tar ~/.ssh) includes the keys
	}
	for _, f := range files {
		if !isNonKeySSHFile(f[1]) {
			return true
		}
	}
	return false // every .ssh reference is a non-key file
}

// isNonKeySSHFile reports whether a .ssh filename is a known non-private-key file.
func isNonKeySSHFile(name string) bool {
	n := strings.ToLower(name)
	return n == "known_hosts" || n == "config" || n == "authorized_keys" || strings.HasSuffix(n, ".pub")
}
