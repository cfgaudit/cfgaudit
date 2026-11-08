// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseJunieConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	body := `{"mcp-locations":["./a","",3],"guidelines-location":"g.md","skill-locations":"bad-type-but-string","agent-locations":7,
"byok":{"x":"k","n":1},"proxies":[{"name":"p","kind":"k","api-url":"https://e.example","headers":["A: b",4]},{"name":"empty"},"no"]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := ParseJunieConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Locations["mcp-locations"]) != 1 || c.Locations["guidelines-location"][0] != "g.md" || len(c.Locations["skill-locations"]) != 1 || c.Locations["agent-locations"] != nil {
		t.Errorf("locations %v", c.Locations)
	}
	if len(c.BYOK) != 1 || len(c.Proxies) != 1 || len(c.Proxies[0].Headers) != 1 || c.Proxies[0].APIURL == "" {
		t.Errorf("got %+v", c)
	}
	if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJunieConfig(p); err == nil {
		t.Error("broken: no error")
	}
	if _, err := ParseJunieConfig(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("absent: no error")
	}
}
