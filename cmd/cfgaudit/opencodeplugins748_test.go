// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// OpenCode 2 plugin directories (#748): folders in .opencode/{plugin,plugins}
// and local paths in the plugin keys, each resolved like Host.resolve.
func TestOpenCodePluginDirs(t *testing.T) {
	root := runFixture(t, map[string]string{
		".opencode/plugin/flat.ts":                   "x",
		".opencode/plugin/srv/server.ts":             "x",
		".opencode/plugin/idx/index.js":              "x",
		".opencode/plugin/nested/server/index.mjs":   "x",
		".opencode/plugins/pkg/package.json":         `{"name": "p", "exports": {".": "./dist/x.js"}}`,
		".opencode/plugins/badpkg/package.json":      `{"exports": "./x.js"}`,
		".opencode/plugins/badpkg/index.ts":          "x",
		".opencode/plugins/gui/gui-experimental.cjs": "x",
		".opencode/plugins/both/index.ts":            "x",
		".opencode/plugins/both/gui-experimental.js": "x",
		".opencode/plugins/empty/readme.md":          "x",
		"opencode.json":                              `{"plugin": ["./local/a", ["./local/b", {}], "-x", "npm-pkg", "../outside", "./local/file.ts"], "plugins": [{"package": "./local/c"}]}`,
		".opencode/opencode.jsonc":                   `{"plugins": ["../local/d"]}`,
		"local/a/index.ts":                           "x",
		"local/b/server.js":                          "x",
		"local/c/index.ts":                           "x",
		"local/d/index.ts":                           "x",
		"local/file.ts":                              "x",
		"opencode.jsonc":                             "{",
	})
	got := map[string]string{}
	for _, f := range scanFindings(t, "--only", "CFG114", root) {
		r, _ := filepath.Rel(root, f.File)
		got[filepath.ToSlash(r)] = string(f.Severity)
		if strings.Contains(f.Message, "plugin directory") && !strings.Contains(f.Message, "OpenCode 2") {
			t.Errorf("message: %s", f.Message)
		}
	}
	want := map[string]string{
		".opencode/plugin/flat.ts":                   "error",
		".opencode/plugin/srv/server.ts":             "error",
		".opencode/plugin/idx/index.js":              "error",
		".opencode/plugin/nested/server/index.mjs":   "error",
		".opencode/plugins/pkg/package.json":         "error",
		".opencode/plugins/badpkg/index.ts":          "error",
		".opencode/plugins/gui/gui-experimental.cjs": "warn",
		".opencode/plugins/both/index.ts":            "error",
		"local/a/index.ts":                           "error",
		"local/b/server.js":                          "error",
		"local/c/index.ts":                           "error",
		"local/d/index.ts":                           "error",
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q (all %v)", k, got[k], v, got)
		}
	}
	if _, _, ok := openCodePluginEntry(filepath.Join(root, "missing")); ok {
		t.Error("missing dir")
	}
}
