// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG121_ProjectGitConfig(t *testing.T) {
	check := func(cfg string) []finding.Finding {
		return CFG121.Check(&Target{ProjectGitConfigFile: ".git/config", ProjectGitConfig: cfg})
	}
	f := check("[core]\n\thooksPath = .githooks\n\tfsmonitor = ./scripts/write-marker\n[attr]\n\ttree = HEAD\n[filter \"fixture\"]\n\tprocess = ./scripts/write-marker\n")
	if len(f) != 1 || f[0].Severity != finding.Error || f[0].File != ".git/config" {
		t.Fatalf("got %+v", f)
	}
	for _, key := range []string{"core.hooksPath", "core.fsmonitor", "filter.fixture.process", "attr.tree"} {
		if !strings.Contains(f[0].Message, key) {
			t.Errorf("no %s in %q", key, f[0].Message)
		}
	}
	if strings.Contains(f[0].Message, "write-marker") {
		t.Errorf("the value leaked: %q", f[0].Message)
	}
	for name, cfg := range map[string]string{
		"remote only":   "[remote \"origin\"]\n\turl = https://example.invalid/repo.git\n",
		"attr alone":    "[attr]\n\ttree = HEAD\n",
		"fsmonitor on":  "[core]\n\tfsmonitor = true\n",
		"lfs":           "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n",
		"own ssh key":   "[core]\n\tsshCommand = ssh -i ~/.ssh/work\n",
		"helper store":  "[credential]\n\thelper = store\n",
		"empty":         "",
		"attr with lfs": "[attr]\n\ttree = HEAD\n[filter \"lfs\"]\n\tprocess = git-lfs filter-process\n",
	} {
		if f := check(cfg); len(f) != 0 {
			t.Errorf("%s: got %+v", name, f)
		}
	}
	for _, v := range []string{".husky", ".husky/_", "./.husky/_"} {
		f := check("[core]\n\thooksPath = " + v + "\n")
		if len(f) != 1 || f[0].Severity != finding.Info {
			t.Errorf("%s: got %+v", v, f)
		}
	}
}

func TestGitCommandKeys_Unchanged(t *testing.T) {
	got := gitCommandKeys("[core]\n\tfsmonitor = true\n\tsshCommand = x\n[diff]\n\texternal = y\n")
	if strings.Join(got, ",") != "core.sshCommand,diff.external" {
		t.Fatalf("got %q", got)
	}
}
