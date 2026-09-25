package rules

import (
	"strings"
	"testing"
)

// A deny block in a discarded file is not a deny block. CFG006 must report the
// missing guardrail and say why the entries in the file do not count (#595).
func TestDiscardedSettings_CFG006_ReportsMissingDeny(t *testing.T) {
	live := settingsTarget(t, `{"cleanupPeriodDays":30,"permissions":{"deny":["Bash(rm -rf *)"]}}`)
	if f := CFG006.Check(live); len(f) != 0 {
		t.Fatalf("a loaded file with a deny block must stay quiet, got %+v", f)
	}

	dead := settingsTarget(t, `{"cleanupPeriodDays":"thirty","permissions":{"deny":["Bash(rm -rf *)"]}}`)
	f := CFG006.Check(dead)
	if len(f) != 1 {
		t.Fatalf("expected CFG006 to fire on a discarded file, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "discards this settings file whole") ||
		!strings.Contains(f[0].Message, "cleanupPeriodDays") {
		t.Errorf("expected the message to explain the discard and name the key, got: %s", f[0].Message)
	}
}

// The file-class rules must not read coverage out of a discarded deny block.
// CFG041 goes quiet either way here — an empty deny is CFG006's job — so the
// test pins what actually changed: the .env class is no longer claimed as
// covered, and CFG042 stops reporting a partial deny as if it were in force.
func TestDiscardedSettings_FileClassRules_DoNotCreditIt(t *testing.T) {
	const perms = `"permissions":{"deny":["Read(**/.env)","Read(**/.env.*)"]}`
	live := settingsTarget(t, `{"cleanupPeriodDays":30,`+perms+`}`)
	dead := settingsTarget(t, `{"cleanupPeriodDays":"thirty",`+perms+`}`)

	if f := CFG042.Check(live); len(f) == 0 {
		t.Fatal("expected CFG042 on a loaded file whose deny does not cover key material")
	}
	if f := CFG042.Check(dead); len(f) != 0 {
		t.Errorf("a discarded file has no deny block for CFG042 to judge, got %+v", f)
	}
	if f := CFG041.Check(dead); len(f) != 0 {
		t.Errorf("a discarded file has no deny block for CFG041 to judge, got %+v", f)
	}
	// What replaces both: one finding that says there is no deny in force.
	if f := CFG006.Check(dead); len(f) != 1 {
		t.Errorf("expected CFG006 to own the discarded case, got %+v", f)
	}
}

// A policy that requires a deny entry is not satisfied by a file Claude Code
// never loads.
func TestDiscardedSettings_PolicyDenyNotSatisfied(t *testing.T) {
	dead := settingsTarget(t, `{"cleanupPeriodDays":"thirty","permissions":{"deny":["Bash(curl:*)"]}}`)
	dead.PolicyRequireDeny = []string{"Bash(curl:*)"}
	if f := CFG025.Check(dead); len(f) != 1 {
		t.Errorf("expected the required deny to be reported as missing, got %+v", f)
	}

	live := settingsTarget(t, `{"cleanupPeriodDays":30,"permissions":{"deny":["Bash(curl:*)"]}}`)
	live.PolicyRequireDeny = []string{"Bash(curl:*)"}
	if f := CFG025.Check(live); len(f) != 0 {
		t.Errorf("a loaded file satisfies the policy, got %+v", f)
	}
}

// The boundary the detection rests on: an unknown key and a malformed value
// deeper inside the file are tolerated upstream, so neither makes the file
// count as discarded.
func TestSettingsDiscarded_OnlyTopLevelTypes(t *testing.T) {
	for _, tc := range []struct {
		json string
		want bool
	}{
		{`{"permissions":{"deny":["Bash(rm *)"]}}`, false},
		{`{"totallyUnknownKeyXyz":1}`, false},
		{`{"apiKeyHelper":null}`, true},
		{`{"cleanupPeriodDays":"thirty"}`, true},
		{`{"model":5}`, true},
	} {
		got := SettingsDiscarded(settingsTarget(t, tc.json).Settings)
		if got != tc.want {
			t.Errorf("SettingsDiscarded(%s) = %v, want %v", tc.json, got, tc.want)
		}
	}
}
