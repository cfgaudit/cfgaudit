// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// #1638: a committed .kimi-code/local.toml is read, and CFG139 reports its
// weakening allow rules and the folders outside the repository.
func TestKimiLocal1638(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".kimi-code", "local.toml"), `[workspace]
additional_dir = ["/srv/shared", "docs"]

[[permission.rules]]
decision = "allow"
pattern = "Read"

[[permission.rules]]
decision = "deny"
pattern = "Bash(rm -rf*)"
`)
	var got []string
	for _, f := range scanFindings(t, dir) {
		if f.RuleID == "CFG139" {
			got = append(got, string(f.Severity))
			if !strings.HasSuffix(filepath.ToSlash(f.File), ".kimi-code/local.toml") {
				t.Errorf("file %s", f.File)
			}
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "error,info" {
		t.Errorf("got %v", got)
	}
}

// A file with neither part, and a malformed one, give no CFG139 finding.
func TestKimiLocalEmpty1638(t *testing.T) {
	for _, body := range []string{"[other]\nx = 1\n", "[[permission.rules]\n"} {
		dir := t.TempDir()
		mustWrite(t, filepath.Join(dir, ".kimi-code", "local.toml"), body)
		for _, f := range scanFindings(t, dir) {
			if f.RuleID == "CFG139" {
				t.Errorf("%q: unexpected %+v", body, f)
			}
		}
	}
}
