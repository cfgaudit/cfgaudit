// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg122 struct{}

var CFG122 = &cfg122{}

func init() { All = append(All, CFG122) }

func (r *cfg122) ID() string { return "CFG122" }

// toolBinaryRe matches a Windows program named like a tool an agent or an
// editor starts by name: git.exe, node.cmd, python.bat. Windows looks in the
// current directory before PATH, so a copy at the root of an unpacked
// archive runs instead of the installed one.
var toolBinaryRe = regexp.MustCompile(`(?i)^(?:git|node|npm|npx|python3?|pip|uv|uvx|code|claude|gh|curl|bash|sh|pwsh|powershell|cmd|where)\.(?:exe|bat|cmd|com|ps1)$`)

// Check reports what an archive carries that a clone of the same repository
// cannot (#1002): a .git entry, which git never puts in a checkout and which
// makes git treat the unpacked folder as a repository with the archive's own
// config (a .git file can point gitdir elsewhere); a tool binary at the root;
// and links, which cfgaudit does not extract. Only an archive scan target
// sets the fields.
func (r *cfg122) Check(t *Target) []finding.Finding {
	if t == nil || t.ArchiveName == "" {
		return nil
	}
	var out []finding.Finding
	gitSeen := map[string]bool{}
	for _, e := range t.ArchiveEntries {
		parts := strings.Split(e, "/")
		for i, p := range parts {
			if p != ".git" {
				continue
			}
			at := strings.Join(parts[:i+1], "/")
			if !gitSeen[at] {
				gitSeen[at] = true
				out = append(out, finding.Finding{RuleID: "CFG122", Severity: finding.Error, File: t.ArchiveName + "/" + at,
					Message: "the archive carries " + at + ", which git clone never produces — unpacked, git treats the folder as a repository with the archive's own config and hooks, so an agent's next git call there runs what they name (a .git file can also point git at another directory). Do not unpack it where an agent works; get the source from the repository instead"})
			}
			break
		}
		if !strings.Contains(e, "/") && toolBinaryRe.MatchString(e) {
			out = append(out, finding.Finding{RuleID: "CFG122", Severity: finding.Error, File: t.ArchiveName + "/" + e,
				Message: "the archive carries " + e + " at its root — on Windows a program in the current directory runs before the installed one, so an agent or editor that starts " + strings.TrimSuffix(strings.ToLower(e), path.Ext(e)) + " in the unpacked folder runs this file. A source archive has no reason to ship it"})
		}
	}
	if len(t.ArchiveLinks) > 0 {
		out = append(out, finding.Finding{RuleID: "CFG122", Severity: finding.Warn, File: t.ArchiveName,
			Message: "the archive carries links (" + quoteList(capList(t.ArchiveLinks, 5)) + andMore(len(t.ArchiveLinks), 5) + "), which cfgaudit does not extract, so the files they stand for were not scanned. Unpacked, a link can point outside the folder; check where each one leads"})
	}
	return out
}
