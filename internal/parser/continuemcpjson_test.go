// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseContinueMCPJSON(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		file, body string
		want       []string
	}{
		{"desktop.json", `{"mcpServers": {"a": {"command": "x"}}}`, []string{"a"}},
		{"code.json", `{"projects": {"/p": {"mcpServers": {"b": {"url": "https://e.com"}}}}}`, []string{"b"}},
		{"single.json", "// jsonc\n{\"command\": \"y\", \"args\": [\"z\"],}", []string{"single"}},
		{"other.json", `{"name": "not a server"}`, nil},
	} {
		p := filepath.Join(dir, tc.file)
		if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := ParseContinueMCPJSON(p)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.file, got, tc.want)
		}
		for _, name := range tc.want {
			if _, ok := got[name]; !ok {
				t.Errorf("%s: missing server %s in %v", tc.file, name, got)
			}
		}
	}
}
