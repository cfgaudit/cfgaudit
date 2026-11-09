// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path/filepath"
	"regexp"
	"strings"

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
	seen := map[string]bool{}
	for _, raw := range t.ExternalImports {
		p := strings.TrimRight(raw, ",.;:)")
		if p == "" || pathAliasRe.MatchString(p) || seen[p] {
			continue // #1210: a TypeScript path alias such as @/components
		}
		seen[p] = true
		sev := finding.Warn
		msg := t.instructionName() + " imports \"@" + p + "\", a file outside the repository: Claude Code loads it into the agent's context after a one-time approval for the project, and nobody reviewing the repository can see what it contains. cfgaudit did not read it." +
			" Commit the imported text into the repository, or decline the external-imports dialog"
		switch {
		case sensitiveImportRe.MatchString(p):
			msg += "; the path names credentials or keys, which would enter the model context"
		case strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "../"):
			// #1210 option B: a personal overlay or a file in a parent
			// workspace reads a file on the developer's own machine; that is
			// a risk only when the file holds secrets.
			sev = finding.Info
			msg += " (a personal or workspace file that names no credentials)"
		}
		out = append(out, finding.Finding{
			RuleID:   "CFG116",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.InstructionFile,
			Message:  msg,
		})
	}
	return out
}

// pathAliasRe is a TypeScript-style path alias written as an import: `@/` and
// one segment without an extension, or `@/*` (#1210). `@/home/...` has two
// segments and stays reported.
var pathAliasRe = regexp.MustCompile(`^/(?:\*|[A-Za-z0-9_-]+)/?$`)

// sensitiveImportRe is an import of credentials or keys: SSH, cloud and
// package-registry credentials, .env files and key files.
var sensitiveImportRe = regexp.MustCompile(`(?i)(?:^|/)(?:\.ssh|\.aws|\.azure|\.gnupg|\.kube|\.docker)(?:/|$)|\.config/gcloud|(?:^|/)\.env(?:\.|$)|(?:^|/)\.(?:netrc|npmrc|pypirc|git-credentials)$|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.(?:pem|key|p12|pfx|jks)$|credentials|secrets?\b`)
