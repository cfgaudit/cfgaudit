// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"testing"
)

// #1189: a task command in any form VS Code accepts, and env values that are
// not strings.
func TestLenientDecoding1189(t *testing.T) {
	for in, want := range map[string]string{
		`{"command":"npm run watch"}`:                           "npm run watch",
		`{"command":["chmod","+x","run.sh"]}`:                   "chmod +x run.sh",
		`{"command":{"value":"./build.sh","quoting":"escape"}}`: "./build.sh",
		`{"command":[{"value":"echo","quoting":"weak"},"hi"]}`:  "echo hi",
		`{"command":null}`:                                      "",
		`{"label":"x"}`:                                         "",
		`{"command":42}`:                                        "42",
	} {
		var task VSCodeTask
		if err := json.Unmarshal([]byte(in), &task); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if task.Command != want {
			t.Errorf("%s: Command = %q, want %q", in, task.Command, want)
		}
	}
	var bad VSCodeTask
	if json.Unmarshal([]byte(`{"label":1}`), &bad) == nil {
		t.Error("a numeric label must still fail")
	}

	var s MCPServer
	if err := json.Unmarshal([]byte(`{"env":{"A":64000,"B":true,"C":null,"D":"x"}}`), &s); err != nil {
		t.Fatal(err)
	}
	if s.Env["A"] != "64000" || s.Env["B"] != "true" || s.Env["C"] != "" || s.Env["D"] != "x" {
		t.Errorf("Env = %v", s.Env)
	}
	if err := json.Unmarshal([]byte(`{"env":null}`), &s); err != nil || s.Env != nil {
		t.Errorf("null env: %v, %v", err, s.Env)
	}
	for _, in := range []string{`{"env":{"A":[1]}}`, `{"env":[1]}`} {
		if json.Unmarshal([]byte(in), &s) == nil {
			t.Errorf("%s: want an error", in)
		}
	}
	if v, err := ParseVSCodeSettingsBytes([]byte(" \n\t"), "s.json"); err != nil || v == nil {
		t.Errorf("empty settings: %v, %v", v, err)
	}
}
