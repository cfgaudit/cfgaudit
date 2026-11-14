// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// A committed .kimi-code/local.toml carries the policy for Kimi Code (#1731):
// CFG025 checks its rules, and CFG118 reports Kimi Code only without the file
// or when .gitignore keeps it out of Git.
func TestPolicy_KimiLocal1731(t *testing.T) {
	policy := "policy:\n  deny:\n    commands: [\"git push\"]\n    read: [\"**/.env\"]\n"
	local := "[[permission.rules]]\ndecision = \"deny\"\npattern = \"Bash(git push{, *, */**})\"\n"

	got := policyFindings(t, runFixture(t, map[string]string{".cfgaudit.yml": policy, ".kimi-code/local.toml": local}))
	if len(got) != 1 || !strings.HasPrefix(got[0], `.kimi-code/local.toml|CFG025|policy deny.read "**/.env": no deny rule in [[permission.rules]] matches Read on ".env"`) ||
		!strings.Contains(got[0], `pattern = "Read(**/.env)"`) {
		t.Fatalf("committed: got %q", got)
	}

	got = policyFindings(t, runFixture(t, map[string]string{".cfgaudit.yml": policy, ".kimi-code/local.toml": local, ".gitignore": ".kimi-code/local.toml\n"}))
	if len(got) != 1 || !strings.HasPrefix(got[0], ".kimi-code|CFG118|") || !strings.Contains(got[0], ".gitignore keeps .kimi-code/local.toml out of Git") {
		t.Fatalf("ignored: got %q", got)
	}

	got = policyFindings(t, runFixture(t, map[string]string{".cfgaudit.yml": policy, ".kimi-code/AGENTS.md": "x\n"}))
	if len(got) != 1 || !strings.HasPrefix(got[0], ".kimi-code|CFG118|") || !strings.Contains(got[0], "commits no .kimi-code/local.toml") {
		t.Fatalf("absent: got %q", got)
	}
}
