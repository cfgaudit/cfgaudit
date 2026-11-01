// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

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
	// grepPatternRe captures a quoted pattern argument passed to grep-like tools.
	grepPatternRe = regexp.MustCompile(`(?i)\b(?:grep|egrep|rg)\b(?:\s+(?:-[^\s]+|--[^\s]+))*\s+('[^']*'|"(?:\\.|[^"])*")`)
	// testPatternRe captures the right-hand pattern in [[ value =~ pattern ]].
	testPatternRe = regexp.MustCompile(`(?s)=~\s*(.*?)\s*\]\]`)
	// caseBodyRe and casePatternRe identify case patterns without masking commands.
	caseBodyRe    = regexp.MustCompile(`(?s)\bcase\b.*?\bin\b(.*?)\besac\b`)
	casePatternRe = regexp.MustCompile(`(?s)(?:^|;;)\s*([^)]*)\)`)
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
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSitesWithScripts(t) {
		if !sshPrivateKeyAccess(site.Command) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "CFG037",
			Severity: finding.Error,
			File:     site.File,
			Message:  site.Label + " reads or copies an SSH private key — exfiltrating it enables lateral movement to every server the developer can reach. A hook must not access ~/.ssh key material" + userScopeNote(t),
		})
	}
	return findings
}

func sshPrivateKeyAccess(cmd string) bool {
	// Ignore key names that are only data in guard-pattern syntax. Keep the
	// command shape intact so a key path used as a separate operand still fires.
	scanText := maskSSHGuardPatterns(cmd)
	// An explicit private-key filename (id_rsa, …) that is not the .pub variant.
	for _, m := range privKeyNameRe.FindAllStringIndex(scanText, -1) {
		if !strings.HasPrefix(scanText[m[1]:], ".pub") {
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

func maskSSHGuardPatterns(cmd string) string {
	masked := []byte(cmd)
	maskMatches := func(re *regexp.Regexp, base int, text string) {
		for _, match := range re.FindAllStringSubmatchIndex(text, -1) {
			if len(match) < 4 || match[2] < 0 {
				continue
			}
			for i := base + match[2]; i < base+match[3]; i++ {
				masked[i] = ' '
			}
		}
	}

	maskMatches(grepPatternRe, 0, cmd)
	maskMatches(testPatternRe, 0, cmd)
	for _, body := range caseBodyRe.FindAllStringSubmatchIndex(cmd, -1) {
		if len(body) < 4 || body[2] < 0 {
			continue
		}
		maskMatches(casePatternRe, body[2], cmd[body[2]:body[3]])
	}
	return string(masked)
}

// isNonKeySSHFile reports whether a .ssh filename is a known non-private-key file.
func isNonKeySSHFile(name string) bool {
	n := strings.ToLower(name)
	return n == "known_hosts" || n == "config" || n == "authorized_keys" || strings.HasSuffix(n, ".pub")
}
