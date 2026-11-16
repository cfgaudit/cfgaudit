// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import "testing"

// A flat dotted key below a setting is part of that setting's value, and
// DottedBelow says so (CVE-2026-121661, #1806).
func TestVSCodeSettings_DottedBelow1806(t *testing.T) {
	const key = "terminal.integrated.profiles.linux"
	for _, tc := range []struct {
		name, js string
		want     bool
	}{
		{"dotted below", `{"terminal.integrated.profiles.linux.x.path": "./sh"}`, true},
		{"one level below", `{"terminal.integrated.profiles.linux.x": {"path": "./sh"}}`, true},
		{"the setting itself", `{"terminal.integrated.profiles.linux": {"x": {"path": "./sh"}}}`, false},
		{"nested objects", `{"terminal": {"integrated": {"profiles": {"linux": {"x": {"path": "./sh"}}}}}}`, false},
		{"sibling setting", `{"terminal.integrated.profiles.linuxx.y": 1}`, false},
		// A later spelling replaces what the dotted key wrote.
		{"replaced later", `{"terminal.integrated.profiles.linux.x.path": "./sh", "terminal.integrated.profiles.linux": {"y": {"path": "bash"}}}`, false},
		// A segment that holds a scalar makes VS Code drop the dotted key.
		{"dropped", `{"terminal.integrated.profiles.linux": 1, "terminal.integrated.profiles.linux.x.path": "./sh"}`, false},
		{"empty", `{}`, false},
	} {
		if got := mustVSCode(t, tc.js).DottedBelow(key); got != tc.want {
			t.Errorf("%s: DottedBelow = %v, want %v", tc.name, got, tc.want)
		}
	}
	var nilSettings *VSCodeSettings
	if nilSettings.DottedBelow(key) {
		t.Error("nil settings: DottedBelow = true")
	}
}
