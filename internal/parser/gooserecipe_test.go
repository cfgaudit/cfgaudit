// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGooseRecipe(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.yaml")
	body := `title: t
description: d
instructions: i
extensions:
  - {type: builtin, name: developer}
  - {type: stdio, name: a, cmd: sh, args: [x, 1], envs: {K: v, N: 2}}
  - {type: stdio, name: a, cmd: sh}
  - {type: stdio, cmd: sh}
  - {type: stdio, name: nocmd}
  - {type: streamable_http, name: h, uri: "https://example.invalid/mcp", headers: {X: y, Z: 3}}
  - {type: streamable_http, name: nouri}
retry:
  on_failure: |
    ./cleanup
    ./more
  checks:
    - {type: shell, command: ./check}
    - {type: shell}
sub_recipes:
  - {name: s, path: sub.yaml}
  - {name: nopath}
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ParseGooseRecipe(p)
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsRecipe || len(r.Servers) != 4 || len(r.Commands) != 2 || len(r.SubRecipes) != 1 {
		t.Fatalf("got %+v", r)
	}
	if s := r.Servers["a"]; s.Command != "sh" || len(s.Args) != 1 || s.Env["K"] != "v" || len(s.Env) != 1 {
		t.Errorf("a: %+v", s)
	}
	if s := r.Servers["h"]; s.URL == "" || s.Type != "http" || len(s.Headers) != 1 {
		t.Errorf("h: %+v", s)
	}
	if c := r.Commands[0]; c.Key != "retry.checks[0].command" || c.Line != 17 {
		t.Errorf("check: %+v", c)
	}
	if c := r.Commands[1]; c.Key != "retry.on_failure" || c.Line != 14 {
		t.Errorf("on_failure: %+v", c)
	}

	if err := os.WriteFile(p, []byte("a: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGooseRecipe(p); err == nil {
		t.Error("broken YAML: no error")
	}
	if _, err := ParseGooseRecipe(filepath.Join(dir, "absent.yaml")); err == nil {
		t.Error("absent file: no error")
	}
}
