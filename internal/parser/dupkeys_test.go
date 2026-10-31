// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"reflect"
	"testing"
)

func TestDuplicateKeys(t *testing.T) {
	doc := `{
  "hooks": {"SessionStart": [], "SessionStart": []},
  "permissions": {
    "deny": ["Bash(curl *)"],
    "deny": []
  },
  "env": {"A": "1"},
  "hooks": {},
  "list": [{"x": 1, "x": 2}, {"x": 3}],
  "hooks": {"Stop": []}
}`
	got := duplicateKeys([]byte(doc))
	want := []DuplicateKey{
		{Path: "hooks.SessionStart", Line: 2, Col: 13, WinLine: 2},
		{Path: "hooks", Line: 2, Col: 3, WinLine: 10},
		{Path: "permissions.deny", Line: 4, Col: 5, WinLine: 5},
		{Path: "hooks", Line: 8, Col: 3, WinLine: 10},
		{Path: "list[0].x", Line: 9, Col: 13, WinLine: 9},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("duplicateKeys =\n%+v\nwant\n%+v", got, want)
	}
}

func TestDuplicateKeys_NoneOrInvalid(t *testing.T) {
	for _, doc := range []string{`{"a": {"b": 1}, "b": {"a": 2}}`, `[{"a": 1}, {"a": 2}]`, `{"a": 1, "a": `, `not json`, `{"a": 1, 1: 2}`, `[{"a": 1}, nul]`,
		`{"//": "see docs", "//": "and this", "_comment": "x", "_comment": "y", "$comment": 1, "$comment": 2}`,
		`{"k\"ey": 1, "x": {"k\"ey": 2}}`} {
		if got := duplicateKeys([]byte(doc)); got != nil {
			t.Errorf("duplicateKeys(%q) = %+v, want nil", doc, got)
		}
	}
}

// ParseSettingsBytes records the duplicates, also behind a BOM, and the
// decoded value is the last occurrence.
func TestParseSettingsBytes_DuplicateKeys(t *testing.T) {
	s, err := ParseSettingsBytes([]byte("\xef\xbb\xbf{\"env\": {\"A\": \"1\"},\n\"env\": {\"A\": \"2\"}}"), "settings.json")
	if err != nil {
		t.Fatal(err)
	}
	if s.Env["A"] != "2" {
		t.Errorf("env.A = %q, want the last occurrence", s.Env["A"])
	}
	if want := []DuplicateKey{{Path: "env", Line: 1, Col: 2, WinLine: 2}}; !reflect.DeepEqual(s.DuplicateKeys, want) {
		t.Errorf("DuplicateKeys = %+v, want %+v", s.DuplicateKeys, want)
	}
}
