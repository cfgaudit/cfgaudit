package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDotEnv(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	body := "# comment\nexport A=1\nB=\"two words\"\nC='x' \nD=plain # trailing\nnot a pair\nA=2\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ParseDotEnv(p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"A": "2", "B": "two words", "C": "x", "D": "plain"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
}
