// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRulesyncPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "permissions.jsonc")
	if p, err := ParseRulesyncPermissions(path); p != nil || err != nil {
		t.Fatalf("absent: %+v %v", p, err)
	}
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{
		// a comment
		"$schema": "x",
		"permission": {"bash": {"git *": "deny"}, "webfetch": "deny", "read": 3},
		"claudecode": {"permission": {"read": {".env": "deny"}}, "env": {}},
		"codexcli": {"approval_policy": "never"},
		"other": 3,
	}`)
	p, err := ParseRulesyncPermissions(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Shared["bash"]["git *"] != "deny" || p.Shared["webfetch"]["*"] != "deny" || p.Shared["read"] != nil {
		t.Errorf("shared: %+v", p.Shared)
	}
	if p.Tools["claudecode"]["read"][".env"] != "deny" || len(p.Tools) != 1 {
		t.Errorf("tools: %+v", p.Tools)
	}
	write(`{`)
	if _, err := ParseRulesyncPermissions(path); err == nil {
		t.Error("broken file")
	}
	write(`{"permission":"allow"}`)
	if p, err := ParseRulesyncPermissions(path); err != nil || p.Shared != nil {
		t.Errorf("wrong shape: %+v %v", p, err)
	}
}
