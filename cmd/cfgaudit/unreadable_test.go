// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// A JSON file that fails on a leading BOM gets a reason that says so, instead
// of Go's "invalid character 'ï'" (#1042).
func TestUnreadableReason_BOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	data := []byte("\xef\xbb\xbf{}")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var v any
	jsonErr := json.Unmarshal(data, &v)
	if jsonErr == nil {
		t.Fatal("encoding/json accepts a leading BOM now; the hint is no longer needed")
	}
	got := unreadableReason(path, fmt.Errorf("parse %s: %w", path, jsonErr))
	if !strings.Contains(got, "starts with a UTF-8 byte order mark") || !strings.Contains(got, "save it as UTF-8 without BOM") {
		t.Errorf("unreadableReason(%v) = %q", jsonErr, got)
	}
	// Both spellings of the BOM, from go1.26 and go1.27 (#1229).
	for _, msg := range []string{
		"invalid character 'ï' looking for beginning of value",
		`invalid character '\ufeff' looking for beginning of value`,
	} {
		if got := unreadableReason(path, errors.New("parse "+path+": "+msg)); !strings.Contains(got, "byte order mark") {
			t.Errorf("unreadableReason(%q) = %q", msg, got)
		}
	}
}

// Any other parse error keeps the parser's message, without the path prefix.
func TestUnreadableReason_Other(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := unreadableReason(path, errors.New("parse "+path+": unexpected end of JSON input")); got != "unexpected end of JSON input" {
		t.Errorf("unreadableReason = %q", got)
	}
	// The same message without a BOM in the file is left as it is.
	const leading = "invalid character 'ï' looking for beginning of value"
	if got := unreadableReason(path, errors.New(leading)); got != leading {
		t.Errorf("unreadableReason = %q", got)
	}
}

// A repository-root .mcp.json with a BOM loads in Claude Code, so it gives the
// findings of the same file without one; .github/mcp.json with a BOM, which
// Copilot CLI skips, stays CFG109 (#1092).
func TestRun_MCPJSONWithBOM(t *testing.T) {
	const mcp = `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@latest","/"]}}}`
	ids := func(files map[string]string) []string {
		t.Helper()
		root := runFixture(t, files)
		_, stdout, stderr := runCLI(t, "--format", "json", "--claude-version", "2.1.314", root)
		var findings []struct{ RuleID, File string }
		if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
			t.Fatalf("json: %v\n%s\n%s", err, stdout, stderr)
		}
		var out []string
		for _, f := range findings {
			rel, err := filepath.Rel(root, f.File)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, f.RuleID+" "+filepath.ToSlash(rel))
		}
		sort.Strings(out)
		return out
	}
	plain := ids(map[string]string{".mcp.json": mcp})
	if len(plain) == 0 {
		t.Fatal("the plain .mcp.json gives no findings; the test needs one")
	}
	if bom := ids(map[string]string{".mcp.json": "\xef\xbb\xbf" + mcp}); !reflect.DeepEqual(bom, plain) {
		t.Errorf("with a BOM: %v\nwithout: %v", bom, plain)
	}
	if got := ids(map[string]string{".mcp.json": "\xef\xbb\xbf \n"}); len(got) != 0 {
		t.Errorf("a .mcp.json with only a BOM and whitespace declares no servers, got %v", got)
	}
	got := ids(map[string]string{".github/mcp.json": "\xef\xbb\xbf" + mcp})
	if !slices.Contains(got, "CFG109 .github/mcp.json") {
		t.Errorf(".github/mcp.json with a BOM: %v, want CFG109", got)
	}
}
