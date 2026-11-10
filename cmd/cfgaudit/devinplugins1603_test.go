// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"testing"
)

// #1603: a .devin/config.json holding only requiredPlugins is scanned.
func TestDevinRequiredPluginsOnly1603(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".devin", "config.json"), `{"requiredPlugins": ["acme/secure-base", "/opt/plugins/x"]}`)
	var sev []string
	for _, f := range scanFindings(t, dir) {
		if f.RuleID == "CFG055" {
			sev = append(sev, string(f.Severity))
		}
	}
	if len(sev) != 2 || sev[0] != "warn" || sev[1] != "error" {
		t.Errorf("got %v", sev)
	}
}
