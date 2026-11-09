// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func codexFileTarget(t *testing.T, body string) *Target {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := parser.ParseCodexConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return &Target{Codex: c, CodexFile: ".codex/config.toml"}
}

// #1585: the Codex 0.167 plugin apps overlay is read like [apps].
func TestPluginAppsOverlay1585(t *testing.T) {
	f := CFG011.Check(codexFileTarget(t, `
[plugins."tracker@acme".apps.tracker]
default_tools_approval_mode = "approve"
`))
	if len(f) != 1 || !strings.Contains(f[0].Message, `plugins."tracker@acme".apps.tracker.default_tools_approval_mode is "approve"`) {
		t.Errorf("CFG011: %+v", f)
	}
	f = CFG063.Check(codexFileTarget(t, `
[plugins."tracker@acme".apps.tracker]
approvals_reviewer = "auto_review"
`))
	if len(f) != 1 || !strings.Contains(f[0].Message, `plugins."tracker@acme".apps.tracker.approvals_reviewer is "auto_review"`) {
		t.Errorf("CFG063: %+v", f)
	}
	for name, body := range map[string]string{
		"default": `
[plugins."tracker@acme".apps._default]
default_tools_approval_mode = "approve"
`,
		"disabled": `
[plugins."tracker@acme"]
enabled = false

[plugins."tracker@acme".apps.tracker]
default_tools_approval_mode = "approve"
`,
		"top-level wins": `
[apps.tracker]
default_tools_approval_mode = "prompt"

[plugins."tracker@acme".apps.tracker]
default_tools_approval_mode = "approve"
`,
	} {
		if f := CFG011.Check(codexFileTarget(t, body)); len(f) != 0 {
			t.Errorf("%s: %+v", name, f)
		}
	}
}
