// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG048_TrustBypass(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want []finding.Severity
		cve  string
	}{
		// CVE-2026-121662: a __proto__ key at any depth.
		{`{"__proto__": {"x": 1}}`, []finding.Severity{finding.Error}, "CVE-2026-121662"},
		{`{"mcp": {"servers": {"__proto__": {"command": "x"}}}}`, []finding.Severity{finding.Error}, "CVE-2026-121662"},
		{`{"editor.__proto__.x": true}`, []finding.Severity{finding.Error}, "CVE-2026-121662"},
		{`{"a": [{"__proto__": 1}]}`, []finding.Severity{finding.Error}, "CVE-2026-121662"},
		{`{"a": "__proto__", "b": {"c": "x.__proto__"}}`, nil, ""},
		{`{"a": {"b.__proto__": 1}}`, nil, ""},
		// CVE-2026-121663: a plain value at a key that groups the trust settings.
		{`{"security.workspace.trust": false}`, []finding.Severity{finding.Error}, "CVE-2026-121663"},
		{`{"security.workspace.trust": false, "security.workspace.trust.enabled": true}`, []finding.Severity{finding.Error}, "CVE-2026-121663"},
		{`{"security.workspace.trust.enabled": true, "security.workspace.trust": "off"}`, []finding.Severity{finding.Error}, "CVE-2026-121663"},
		{`{"security": {"workspace": 0}}`, []finding.Severity{finding.Error}, "CVE-2026-121663"},
		{`{"security.workspace.trust.enabled": true}`, nil, ""},
		{`{"security.workspace.trust": {"enabled": true, "untrustedFiles": "prompt"}}`, nil, ""},
		{`{"security.workspace.trust": null}`, nil, ""},
		// CVE-2026-121665: experiment treatment overrides.
		{`{"experiments.override.someTreatment": "x"}`, []finding.Severity{finding.Warn}, "CVE-2026-121665"},
		{`{"experiments": {"override": {"t1": true}}}`, []finding.Severity{finding.Warn}, "CVE-2026-121665"},
		{`{"experiments.override": {}}`, nil, ""},
		{`{"experiments.override": "x"}`, nil, ""},
		{`{}`, nil, ""},
	} {
		var got []finding.Severity
		var msgs []string
		for _, f := range CFG048.Check(agentHostTarget(t, tc.src)) {
			if strings.Contains(f.Message, "CVE-2026-12166") {
				got = append(got, f.Severity)
				msgs = append(msgs, f.Message)
			}
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v (%q)", tc.src, got, tc.want, msgs)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] || !strings.Contains(msgs[i], tc.cve) || !strings.Contains(msgs[i], "1.145.3") {
				t.Errorf("%s: got %v %q, want %v naming %s", tc.src, got[i], msgs[i], tc.want[i], tc.cve)
			}
		}
	}
}

func TestCFG048_TrustBypassPaths(t *testing.T) {
	f := CFG048.Check(agentHostTarget(t, `{"mcp": {"servers": {"__proto__": {}}}, "x.__proto__": 1}`))
	for _, x := range f {
		if x.Key == "__proto__" {
			if !strings.Contains(x.Message, "mcp > servers > __proto__") || !strings.Contains(x.Message, "x.__proto__") {
				t.Errorf("paths missing: %q", x.Message)
			}
			return
		}
	}
	t.Fatal("no __proto__ finding")
}
