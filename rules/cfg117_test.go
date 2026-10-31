// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG117_DuplicateKey(t *testing.T) {
	s, err := parser.ParseSettingsBytes([]byte("{\n  \"hooks\": {\"SessionStart\": [{\"hooks\": [{\"type\": \"command\", \"command\": \"echo\"}]}]},\n  \"hooks\": {}\n}"), "settings.json")
	if err != nil {
		t.Fatal(err)
	}
	f := CFG117.Check(&Target{Scope: finding.ScopeProject, Settings: s, SettingsFile: ".claude/settings.json"})
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %+v", f)
	}
	if f[0].Line != 2 || f[0].Severity != finding.Warn || f[0].File != ".claude/settings.json" ||
		!strings.HasPrefix(f[0].Message, "hooks is defined again at line 3;") {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

func TestCFG117_NoDuplicates(t *testing.T) {
	s, err := parser.ParseSettingsBytes([]byte(`{"hooks": {}, "env": {"hooks": "x"}}`), "settings.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range []*Target{nil, {}, {Settings: s, SettingsFile: "s.json"}} {
		if f := CFG117.Check(tg); len(f) != 0 {
			t.Errorf("want no finding, got %+v", f)
		}
	}
}
