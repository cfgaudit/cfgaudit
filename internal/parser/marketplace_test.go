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
