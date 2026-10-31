// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if jsonErr == nil || !strings.Contains(jsonErr.Error(), bomJSONError) {
		t.Fatalf("encoding/json no longer reports a BOM as %q: %v", bomJSONError, jsonErr)
	}
	got := unreadableReason(path, fmt.Errorf("parse %s: %w", path, jsonErr))
	if !strings.Contains(got, "starts with a UTF-8 byte order mark") || !strings.Contains(got, "save it as UTF-8 without BOM") {
		t.Errorf("unreadableReason = %q", got)
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
	// The 'ï' message without a BOM in the file is left as it is.
	if got := unreadableReason(path, errors.New(bomJSONError)); got != bomJSONError {
		t.Errorf("unreadableReason = %q", got)
	}
}
