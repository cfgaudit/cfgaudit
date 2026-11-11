// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"testing"
)

// #1666: a per-platform task command in any form VS Code accepts, and an MCP
// `auth` value that is not Cursor's static OAuth object.
func TestLenientDecoding1666(t *testing.T) {
	var task VSCodeTask
	in := `{"command":"make","args":["all"],"windows":{"command":["cmd","/c","build.bat"]},"osx":{"command":{"value":"./build.sh","quoting":"escape"}}}`
	if err := json.Unmarshal([]byte(in), &task); err != nil {
		t.Fatal(err)
	}
	if task.Windows == nil || task.Windows.Command != "cmd /c build.bat" {
		t.Errorf("windows.command = %+v", task.Windows)
	}
	if task.OSX == nil || task.OSX.Command != "./build.sh" {
		t.Errorf("osx.command = %+v", task.OSX)
	}
	got := task.CommandLines()
	want := []string{"make all", "cmd /c build.bat all", "./build.sh all"}
	if len(got) != len(want) {
		t.Fatalf("CommandLines() = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("CommandLines()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	var bad VSCodeTask
	if json.Unmarshal([]byte(`{"windows":{"args":"x"}}`), &bad) == nil {
		t.Error("a string windows.args must still fail")
	}

	for in, want := range map[string]string{
		`{"url":"https://x.example/mcp","auth":"oauth"}`:                        "",
		`{"url":"https://x.example/mcp","auth":true}`:                           "",
		`{"url":"https://x.example/mcp","auth":["oauth"]}`:                      "",
		`{"url":"https://x.example/mcp","auth":null}`:                           "",
		`{"url":"https://x.example/mcp","auth":{"CLIENT_SECRET":"s"}}`:          "s",
		`{"url":"https://x.example/mcp","auth":{"CLIENT_ID":"id","scopes":[]}}`: "",
	} {
		var s MCPServer
		if err := json.Unmarshal([]byte(in), &s); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		got := ""
		if s.Auth != nil {
			got = s.Auth.ClientSecret
		}
		if got != want {
			t.Errorf("%s: ClientSecret = %q, want %q", in, got, want)
		}
	}
	var s MCPServer
	if json.Unmarshal([]byte(`{"auth":{"CLIENT_SECRET":1}}`), &s) == nil {
		t.Error("a numeric CLIENT_SECRET in an auth object must still fail")
	}
}
