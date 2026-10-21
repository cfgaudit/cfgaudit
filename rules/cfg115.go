// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg115 struct{}

var CFG115 = &cfg115{}

func init() { All = append(All, CFG115) }

func (r *cfg115) ID() string { return "CFG115" }

// Check reports a path in the scanned repository that is, or passes through, a
// symbolic link resolving outside the repository.
//
// The operating system follows the link for every reader. An agent that loads
// .claude/settings.json, .mcp.json or CLAUDE.md through such a link loads a
// file from the machine that checked the repository out, not from the
// repository, so what the repository appears to declare and what the agent
// reads differ. cfgaudit used to follow the link too, reading and quoting a
// file outside the directory it was asked to scan (GHSA-x9h6-c6v9-v699). It no
// longer opens the target; this rule makes the skipped file visible instead of
// letting it pass as absent.
//
// Warn, not error: the link's content is unknown by design, so nothing is
// claimed about what it configures, only that the repository hands the choice
// to whatever exists at that path on the reader's machine.
func (r *cfg115) Check(t *Target) []finding.Finding {
	if t == nil || t.EscapedLink == "" {
		return nil
	}
	link := t.EscapedTarget
	if link == "" {
		link = "a path outside the repository"
	} else {
		link = "\"" + filepath.ToSlash(link) + "\""
	}
	return []finding.Finding{{
		RuleID:   "CFG115",
		Severity: finding.Warn,
		Scope:    t.Scope,
		File:     t.EscapedLink,
		Message: "this path is a symbolic link to " + link + ", outside the scanned repository. An agent that opens it loads a file from the machine that checked the repository out, not from the repository." +
			" cfgaudit did not read it and no other rule ran on it. Commit the file itself instead of a link",
	}}
}
