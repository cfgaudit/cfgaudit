// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG121_NestedRepos994(t *testing.T) {
	tg := &Target{NestedRepos: []NestedRepo{
		{ConfigFile: "a/config", Config: "[core]\n\tbare = true\n\tfsmonitor = touch /tmp/m\n"},
		{ConfigFile: "b/config", Config: "# c\n[core]\n\tfsmonitor = true\n[remote \"origin\"]\n\turl = x\n"},
		{ConfigFile: "c/config", Config: "[filter \"lfs\"]\n\tsmudge = git-lfs smudge %f\n[diff]\n\texternal = ./x.sh\n"},
		{ConfigFile: "d/config", Config: "[]\n[core]\n\thooksPath\n"},
	}}
	f := CFG121.Check(tg)
	want := map[string]finding.Severity{"a/config": finding.Error, "b/config": finding.Warn, "c/config": finding.Error, "d/config": finding.Error}
	if len(f) != len(want) {
		t.Fatalf("got %+v", f)
	}
	for _, x := range f {
		if want[x.File] != x.Severity {
			t.Errorf("%s: %s, want %s (%s)", x.File, x.Severity, want[x.File], x.Message)
		}
	}
	if !strings.Contains(f[2].Message, `"filter.lfs.smudge", "diff.external"`) {
		t.Errorf("keys: %s", f[2].Message)
	}
	if CFG121.Check(nil) != nil {
		t.Error("nil target")
	}
}

func TestCFG121_GitModules994(t *testing.T) {
	mods := "[submodule \"a\"]\n\turl = https://github.com/org/a.git\n" +
		"\turl = https://githu6.com/org/b.git\n" +
		"\turl = git@github.com.evil.io:org/c.git\n" +
		"\turl = http://example.com/d.git\n" +
		"\turl = git://github.com/e.git\n" +
		"\turl = https://gitlab.company.com/x/f.git\n" +
		"\turl = ../sibling.git\n" +
		"\turl = https://gist.github.com/x.git\n" +
		"\turl = https://xn--gthub-cta.com/x.git\n" +
		"\turl = \"https://gіthub.com/x.git\"\n" +
		"\turl = https://%zz/x.git\n" +
		"\turl = git@bitbucket.org:o/r.git\n"
	f := CFG121.Check(&Target{GitModules: mods, GitModulesFile: ".gitmodules"})
	var lines []string
	for _, x := range f {
		if x.Severity != finding.Warn {
			t.Errorf("%+v", x)
		}
		lines = append(lines, strconv.Itoa(x.Line))
	}
	if got := strings.Join(lines, ","); got != "3,4,5,6,10,11" {
		t.Errorf("lines %s: %+v", got, f)
	}
}
