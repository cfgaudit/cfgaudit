// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg027 struct{}

var CFG027 = &cfg027{}

func init() { All = append(All, CFG027) }

func (r *cfg027) ID() string { return "CFG027" }

// persistencePatterns match commands that install OS-level persistence — they
// survive reboots and new shell sessions and run outside Claude Code entirely.
// A pattern with write set names a path: it counts only when the command
// writes to that path (writePaths), not when it reads or tests it (#892).
var persistencePatterns = []struct {
	re    *regexp.Regexp
	label string
	write bool
}{
	{regexp.MustCompile(`\bcrontab\b`), "crontab (cron job)", false},
	{regexp.MustCompile(`/etc/cron`), "system cron directory", true},
	{regexp.MustCompile(`(?:^|[\s/~"'$}])\.(?:bashrc|zshrc|bash_profile|zprofile|bash_login|zshenv|profile)\b`), "shell startup file", true},
	{regexp.MustCompile(`/etc/profile`), "shell startup file", true},
	{regexp.MustCompile(`\bsystemctl\s+(?:--user\s+)?enable\b`), "systemd service enable", false},
	{regexp.MustCompile(`/(?:etc|\.config)/systemd/`), "systemd unit directory", true},
	{regexp.MustCompile(`\blaunchctl\s+(?:load|bootstrap|enable)\b`), "launchd agent", false},
	{regexp.MustCompile(`\b(?:LaunchAgents|LaunchDaemons)\b`), "launchd plist directory", true},
}

// redirectTargetRe is a > or >> redirect and the word it writes to.
var redirectTargetRe = regexp.MustCompile(`>>?\|?\s*([^\s<>;|&()]+)`)

// commandPrefixWords come before the program name in a shell segment.
var commandPrefixWords = map[string]bool{
	"then": true, "do": true, "else": true, "elif": true, "{": true, "!": true,
	"sudo": true, "env": true, "exec": true, "command": true, "time": true, "nohup": true,
}

// writePaths returns the paths cmd writes to: redirect and tee targets, the
// destination of cp, mv, install, ln and rsync, dd's of=, the files of sed -i,
// and the operands of chmod, chown, chgrp, touch and truncate. Reading a
// startup file ("cat /etc/profile.d/x.sh", "[ -s ~/.bashrc ]") or sourcing
// one installs nothing.
func writePaths(cmd string) []string {
	var out []string
	for _, line := range strings.Split(cmd, "\n") {
		for _, seg := range splitCommands(line) {
			for _, m := range redirectTargetRe.FindAllStringSubmatch(seg, -1) {
				out = append(out, m[1])
			}
			fields := strings.Fields(seg)
			i := 0
			for i < len(fields) {
				f := strings.TrimLeft(fields[i], "(")
				if f == "" || commandPrefixWords[f] || (strings.Contains(f, "=") && !strings.HasPrefix(f, "-")) {
					i++
					continue
				}
				break
			}
			if i >= len(fields) {
				continue
			}
			var operands []string
			inPlace := false
			for _, a := range fields[i+1:] {
				if strings.HasPrefix(a, ">") || strings.HasPrefix(a, "2>") {
					break
				}
				if strings.HasPrefix(a, "-") {
					inPlace = inPlace || strings.HasPrefix(a, "-i") || a == "--in-place"
					continue
				}
				operands = append(operands, a)
			}
			switch path.Base(strings.TrimLeft(fields[i], "(")) {
			case "cp", "mv", "install", "ln", "rsync":
				if len(operands) > 0 {
					out = append(out, operands[len(operands)-1])
				}
			case "dd":
				for _, a := range operands {
					if strings.HasPrefix(a, "of=") {
						out = append(out, a[3:])
					}
				}
			case "sed":
				if inPlace {
					out = append(out, operands...)
				}
			case "tee", "chmod", "chown", "chgrp", "touch", "truncate":
				out = append(out, operands...)
			}
		}
	}
	for i, p := range out {
		out[i] = strings.Trim(p, `'"`+"`)")
	}
	return out
}

// writesTo reports whether cmd writes to a path re matches.
func writesTo(cmd string, re *regexp.Regexp) bool {
	for _, p := range writePaths(cmd) {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

// Check flags command sites that install a persistence mechanism (cron, shell
// startup files, systemd, launchd). Scans hooks and command-running helpers.
func (r *cfg027) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, site := range commandSites(t) {
		seen := map[string]bool{}
		for _, p := range persistencePatterns {
			if seen[p.label] || !p.re.MatchString(site.Command) || (p.write && !writesTo(site.Command, p.re)) {
				continue
			}
			seen[p.label] = true
			findings = append(findings, finding.Finding{
				RuleID:   "CFG027",
				Severity: finding.Error,
				File:     site.File,
				Message: site.Label + " installs a persistence mechanism (" + p.label +
					") — it survives reboots and new sessions and runs outside Claude Code; a hook should never modify cron, shell startup files, or system services" + userScopeNote(t),
			})
		}
	}
	return findings
}
