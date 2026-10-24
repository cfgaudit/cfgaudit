// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg116 struct{}

var CFG116 = &cfg116{}

func init() { All = append(All, CFG116) }

func (r *cfg116) ID() string { return "CFG116" }

// Check reports a committed Claude Code instruction file whose `@path` import
// resolves outside the repository (#794): `@~/...`, an absolute path elsewhere,
// or `../` past the root.
//
// Claude Code loads the imported file into the same context as the file that
// imports it, so the repository decides which file on the reader's machine the
// agent reads as instructions: `@~/.aws/credentials` puts a secret in front of
// a model that the rest of the context may tell to send it somewhere. A
// reviewer cannot see what the file holds, and cfgaudit does not read it.
//
// Warn, not error: measured with 2.1.310 in print mode, such an import is not
// loaded, and an interactive session loads it only after a once-per-project
// approval dialog that lists the files. The finding is there so that dialog is
// not the only thing between the repository and the file. CLAUDE.local.md is
// left out: it is the personal, usually gitignored file, and the memory docs
// suggest a home-directory import in it to share preferences across worktrees.
func (r *cfg116) Check(t *Target) []finding.Finding {
	if t == nil || len(t.ExternalImports) == 0 || t.Scope != finding.ScopeProject ||
		filepath.Base(t.InstructionFile) == "CLAUDE.local.md" {
		return nil
	}
	var out []finding.Finding
	for _, p := range t.ExternalImports {
		out = append(out, finding.Finding{
			RuleID:   "CFG116",
			Severity: finding.Warn,
			Scope:    t.Scope,
			File:     t.InstructionFile,
			Message: t.instructionName() + " imports \"@" + p + "\", a file outside the repository: Claude Code loads it into the agent's context after a one-time approval for the project, and nobody reviewing the repository can see what it contains. cfgaudit did not read it." +
				" Commit the imported text into the repository, or decline the external-imports dialog",
		})
	}
	return out
}
