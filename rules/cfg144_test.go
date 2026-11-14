// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// One info finding per outside entry; the message says what Antigravity does
// with it for the manifest and field it is in (#1639).
func TestCFG144_Entries1639(t *testing.T) {
	tg := &Target{AntigravityOutside: []AntigravityOutsideEntry{
		{File: "/r/.agents/skills.json", Field: "entries", Index: 1, Path: "/data/skills", Reason: "an absolute path"},
		{File: "/r/.agents/rules.json", Field: "entries", Index: 0, Path: "../shared-rules", Reason: "it leaves the repository through ../"},
		{File: "/r/.agents/plugins.json", Field: "inherits", Index: 2, Path: "../x/.agents/plugins.json", Reason: "it leaves the repository through ../"},
	}}
	f := CFG144.Check(tg)
	if len(f) != 3 {
		t.Fatalf("got %+v", f)
	}
	for i, want := range []string{
		`skills.json entries[1].path "/data/skills" points outside the repository (an absolute path). Antigravity CLI 1.5.2 and later skip it`,
		`rules.json entries[0].path "../shared-rules" points outside the repository (it leaves the repository through ../). The Antigravity docs show such paths loading from rules.json`,
		`plugins.json inherits[2].path "../x/.agents/plugins.json" points outside the repository (it leaves the repository through ../). Antigravity CLI adds the entries of the manifest it names`,
	} {
		if f[i].Severity != finding.Info || f[i].File != tg.AntigravityOutside[i].File || !strings.Contains(f[i].Message, want) {
			t.Errorf("finding %d: %+v, want %q", i, f[i], want)
		}
	}
	if CFG144.Check(nil) != nil || len(CFG144.Check(&Target{})) != 0 || CFG144.ID() != "CFG144" {
		t.Error("nil target, empty target or ID")
	}
}
