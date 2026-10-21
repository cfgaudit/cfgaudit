// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
)

func mustVSCode(t *testing.T, js string) *VSCodeSettings {
	t.Helper()
	s, err := ParseVSCodeSettingsBytes([]byte(js), "settings.json")
	if err != nil {
		t.Fatalf("parse %s: %v", js, err)
	}
	return s
}

// The cases follow toValuesTree/addToValueTree in VS Code's configuration.ts:
// top-level keys in file order, each split on "." and assigned at that path.
func TestVSCodeSettings_NestedForm(t *testing.T) {
	const key = "chat.tools.global.autoApprove"
	for _, tc := range []struct {
		name     string
		js       string
		val, set bool
		nested   bool
	}{
		{"flat", `{"chat.tools.global.autoApprove": true}`, true, true, false},
		{"nested", `{"chat": {"tools": {"global": {"autoApprove": true}}}}`, true, true, true},
		{"partly nested", `{"chat.tools": {"global.autoApprove": false, "global": {"autoApprove": true}}}`, true, true, true},
		{"JSONC nested", "{\n // comment\n \"chat\": {\"tools\": {\"global\": {\"autoApprove\": true,},},},\n}", true, true, true},
		// A dotted key inside an object is not split, so VS Code never reads it.
		{"dotted key inside an object", `{"chat": {"tools.global.autoApprove": true}}`, false, false, false},
		// A later nested object replaces the whole subtree the flat key wrote into.
		{"flat then nested object", `{"chat.tools.global.autoApprove": true, "chat": {"editor": {"fontSize": 12}}}`, false, false, false},
		{"flat then nested override", `{"chat.tools.global.autoApprove": false, "chat": {"tools": {"global": {"autoApprove": true}}}}`, true, true, true},
		// A later flat key writes into the nested object.
		{"nested then flat", `{"chat": {"tools": {"global": {"autoApprove": true}}}, "chat.tools.global.autoApprove": false}`, false, true, false},
		// A segment that already holds a value blocks the key: "Ignoring ... as chat is ...".
		{"segment is a scalar", `{"chat": 1, "chat.tools.global.autoApprove": true}`, false, false, false},
		{"segment is null", `{"chat": null, "chat.tools.global.autoApprove": true}`, false, false, false},
	} {
		s := mustVSCode(t, tc.js)
		val, set := s.BoolField(key)
		if val != tc.val || set != tc.set {
			t.Errorf("%s: BoolField = (%v, %v), want (%v, %v)", tc.name, val, set, tc.val, tc.set)
		}
		if got := s.Nested(key); got != tc.nested {
			t.Errorf("%s: Nested = %v, want %v", tc.name, got, tc.nested)
		}
	}
}

// Object-valued settings keep their own dotted-looking keys as data: the
// terminal auto-approve map is keyed by command patterns.
func TestVSCodeSettings_NestedObjectValue(t *testing.T) {
	s := mustVSCode(t, `{"chat": {"tools": {"terminal": {"autoApprove": {"/.*/": true, "npm.run": true}}}}}`)
	m, ok := s.ObjectField("chat.tools.terminal.autoApprove")
	if !ok || len(m) != 2 || string(m["/.*/"]) != "true" || string(m["npm.run"]) != "true" {
		t.Fatalf("ObjectField = %v, %v", m, ok)
	}
	if _, ok := s.ObjectField("chat.tools.terminal.autoApprove.npm"); ok {
		t.Error("a key inside an object-valued setting must not be split into a path")
	}
}

// A struct built from Raw alone (as tests do) still answers lookups.
func TestVSCodeSettings_FromRawOnly(t *testing.T) {
	s := &VSCodeSettings{Raw: mustVSCode(t, `{"chat": {"permissions": {"default": "autopilot"}}}`).Raw}
	if v, ok := s.StringField("chat.permissions.default"); !ok || v != "autopilot" {
		t.Fatalf("StringField = %q, %v", v, ok)
	}
}

// Typed accessors report present=false for a missing key and for a value of
// the wrong type, and a nil settings value answers nothing.
func TestVSCodeSettings_TypedAccessorsMismatch(t *testing.T) {
	s := mustVSCode(t, `{"a.str": "x", "a.num": 3, "a.obj": {"k": 1}}`)
	if v, ok := s.StringField("a.str"); !ok || v != "x" {
		t.Errorf("StringField(a.str) = %q, %v", v, ok)
	}
	if _, ok := s.StringField("a.num"); ok {
		t.Error("a number is not a string")
	}
	if _, ok := s.StringField("a.missing"); ok {
		t.Error("a missing key is not present")
	}
	if _, ok := s.ObjectField("a.str"); ok {
		t.Error("a string is not an object")
	}
	if _, ok := s.ObjectField("b"); ok {
		t.Error("a missing key is not present")
	}
	if raw, ok := s.RawValue("a.num"); !ok || string(raw) != "3" {
		t.Errorf("RawValue(a.num) = %s, %v", raw, ok)
	}
	var nilSettings *VSCodeSettings
	if _, ok := nilSettings.RawValue("a.str"); ok {
		t.Error("nil settings must answer nothing")
	}
}

func TestParseVSCodeFiles_MissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	if _, err := ParseVSCodeSettings(missing); err == nil {
		t.Error("ParseVSCodeSettings: expected an error for a missing file")
	}
	if _, err := ParseVSCodeTasks(missing); err == nil {
		t.Error("ParseVSCodeTasks: expected an error for a missing file")
	}
}

func TestJSONEqual(t *testing.T) {
	if !jsonEqual(json.RawMessage(`{"a": [1, 2]}`), json.RawMessage(`{"a":[1,2]}`)) {
		t.Error("whitespace must not matter")
	}
	if jsonEqual(json.RawMessage(`{`), json.RawMessage(`{`)) {
		t.Error("undecodable values are never equal")
	}
}

// A repeated key keeps its first position; anything that is not a well-formed
// object yields no order.
func TestTopLevelKeyOrder(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{`{"b": 1, "a": {"x": 2}, "b": 3}`, []string{"b", "a"}},
		{`[1, 2]`, nil},
		{``, nil},
		{`{1: 2}`, nil},
		{`{"a": }`, nil},
	} {
		if got := topLevelKeyOrder([]byte(tc.in)); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: got %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A trailing comma is dropped together with the whitespace after it, CRLF
// included, and a closing bracket with nothing before it is left alone.
func TestStripJSONC_TrailingCommaEdges(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"{\"a\": 1,\r\n}", "{\"a\": 1}"},
		{"}", "}"},
		{"[1, 2 ,\t]", "[1, 2 ]"},
	} {
		if got := string(stripJSONC([]byte(tc.in))); got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}
