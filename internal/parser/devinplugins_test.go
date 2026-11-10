// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDevinRequiredPluginSources1603(t *testing.T) {
	var raw []json.RawMessage
	if err := json.Unmarshal([]byte(`[
		"acme/base", "", " ", "https://gitlab.example/x.git", "git@github.com:acme/y.git", "./local", "C:\\plugins\\z",
		{"source": "github", "repo": "acme/r", "path": "plugins/p"},
		{"source": "github"},
		{"source": "local", "path": "/abs"},
		{"source": "url", "url": "https://e.example/a.git"},
		"not json"
	]`), &raw); err != nil {
		t.Fatal(err)
	}
	raw = append(raw, json.RawMessage(`[1]`))
	got := (&DevinConfig{RequiredPlugins: raw}).RequiredPluginSources()
	want := []DevinPluginSource{
		{"github", "acme/base"}, {"url", "https://gitlab.example/x.git"}, {"url", "git@github.com:acme/y.git"},
		{"local", "./local"}, {"local", `C:\plugins\z`}, {"github", "acme/r#plugins/p"},
		{"local", "/abs"}, {"url", "https://e.example/a.git"}, {"github", "not json"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
	if (*DevinConfig)(nil).RequiredPluginSources() != nil {
		t.Error("nil config")
	}
}
