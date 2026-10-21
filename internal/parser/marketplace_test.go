// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// A real committed marketplace.json carries a UTF-8 BOM, which json.Unmarshal
// rejects. Found by the 504-repo pre-release run.
func TestParseMarketplace_ByteOrderMark(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "marketplace.json")
	body := "\xEF\xBB\xBF{\"name\":\"m\",\"plugins\":[{\"name\":\"p\",\"source\":\"./p\"}]}"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := ParseMarketplace(path)
	if err != nil {
		t.Fatalf("a BOM must not fail the parse: %v", err)
	}
	if len(m.Plugins) != 1 {
		t.Errorf("got %+v", m.Plugins)
	}
}

// Only object sources naming a type are external fetches. The string shorthand,
// an entry without a source, and an object with no type are skipped; the type
// may be spelled "source" or "type".
func TestMarketplace_ExternalSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marketplace.json")
	body := `{"name": "m", "plugins": [
      {"name": "local", "source": "./plugins/local"},
      {"name": "nosource"},
      {"name": "typeless", "source": {"repo": "o/r"}},
      {"name": " gh ", "source": {"source": " GitHub ", "repo": "o/gh"}},
      {"source": {"type": "url", "url": "https://example.com/p.git"}}
    ]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := ParseMarketplace(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := m.ExternalSources()
	if len(got) != 2 {
		t.Fatalf("expected 2 external sources, got %+v", got)
	}
	if got[0].Plugin != "gh" || got[0].Source.Kind() != "github" || got[0].Source.Repo != "o/gh" {
		t.Errorf("first source = %+v", got[0])
	}
	if got[1].Plugin != "(unnamed)" || got[1].Source.Kind() != "url" {
		t.Errorf("second source = %+v", got[1])
	}
	var nilM *Marketplace
	if nilM.ExternalSources() != nil {
		t.Error("a nil marketplace has no sources")
	}
}
