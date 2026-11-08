// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG132(t *testing.T) {
	if CFG132.Check(nil) != nil || CFG132.Check(&Target{}) != nil {
		t.Fatal("empty target")
	}
	c := &parser.OpenCodeConfig{
		Instructions: []string{"docs/a.md", "~/notes/**/*.md", "~/.aws/credentials", "https://example.com/r.md", "/etc/x.md", "../up.md", `C:\x\id_rsa`, "./ok/*.md"},
		Skills:       []byte(`["team", "~/s", "https://example.com/s", "..", "/abs"]`),
	}
	got := map[finding.Severity]int{}
	for _, f := range CFG132.Check(&Target{OpenCode: c, OpenCodeFile: "opencode.json"}) {
		got[f.Severity]++
	}
	if got[finding.Error] != 2 || got[finding.Warn] != 8 {
		t.Fatalf("got %v", got)
	}
	f := CFG132.Check(&Target{OpenCode: &parser.OpenCodeConfig{Instructions: []string{"../x.md"}, Skills: []byte(`["../s", "~/s"]`)}, OpenCodeFile: ".opencode/opencode.json"})
	if len(f) != 3 || !strings.Contains(f[0].Message, "drop the leading ../") || !strings.Contains(f[1].Message, "drop the leading ../") || strings.Contains(f[2].Message, "drop the leading") {
		t.Fatalf("hint: %+v", f)
	}
	for in, want := range map[string]string{"a": "", "./a/../b": "", "HTTPS://x": "url", "~": "home", `\\srv\x`: "absolute", "D:x": "absolute", "a/../../b": "parent"} {
		if got := OpenCodeOutside(in); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}
