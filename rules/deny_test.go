package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/version"
)

func ver(major, minor, patch int) *version.Version {
	return &version.Version{Major: major, Minor: minor, Patch: patch}
}

func TestDenyCoversEverything(t *testing.T) {
	cases := []struct {
		name string
		deny []string
		ver  *version.Version
		want bool
	}{
		// bare "*" deny-all glob — version-gated on 2.1.166
		{"star unknown version", []string{"*"}, nil, true},
		{"star at min version", []string{"*"}, ver(2, 1, 166), true},
		{"star above min version", []string{"*"}, ver(2, 2, 0), true},
		{"star just below min version", []string{"*"}, ver(2, 1, 165), false},
		{"star far below min version", []string{"*"}, ver(2, 0, 999), false},

		// Read-all wildcards — version-independent
		{"Read(*) old version", []string{"Read(*)"}, ver(1, 0, 0), true},
		{"Read(**) unknown version", []string{"Read(**)"}, nil, true},
		{"Read(**/*) below glob version", []string{"Read(**/*)"}, ver(2, 1, 100), true},
		{"Read with whitespace", []string{" Read(**) "}, ver(2, 1, 100), true},
		{"read lowercase tool", []string{"read(**)"}, ver(2, 1, 100), true},

		// not deny-all
		{"specific env read", []string{"Read(.env)"}, ver(2, 2, 0), false},
		{"bash wildcard is not deny-all", []string{"Bash(rm -rf *)"}, ver(2, 2, 0), false},
		{"Read of single segment glob in path only", []string{"Edit(*)"}, ver(2, 2, 0), false},
		{"empty deny", nil, ver(2, 2, 0), false},
		{"mixed, star present and active", []string{"Read(.env)", "*"}, ver(2, 1, 166), true},
		{"mixed, star present but inactive", []string{"Read(.env)", "*"}, ver(2, 1, 165), false},
	}
	for _, c := range cases {
		if got := denyCoversEverything(c.deny, c.ver); got != c.want {
			t.Errorf("%s: denyCoversEverything(%v, %v) = %v, want %v", c.name, c.deny, c.ver, got, c.want)
		}
	}
}

// denyTarget builds a settings target with the given deny entries and detected
// Claude version, to exercise the CFG041–044 deny-all suppression.
func denyTarget(t *testing.T, denyJSON string, v *version.Version) *Target {
	t.Helper()
	tgt := settingsTarget(t, `{"permissions":{"deny":[`+denyJSON+`]}}`)
	tgt.ClaudeVersion = v
	return tgt
}

func TestCFG041to044_DenyAllStar_Suppressed(t *testing.T) {
	rules := []Rule{CFG041, CFG042, CFG043, CFG044}
	// On >= 2.1.166 (and unknown version), a bare "*" denies all tools — no per-class gap.
	for _, v := range []*version.Version{nil, ver(2, 1, 166), ver(2, 2, 5)} {
		tgt := denyTarget(t, `"*"`, v)
		for _, r := range rules {
			if f := r.Check(tgt); len(f) != 0 {
				t.Errorf("%s with deny [\"*\"] at version %v: expected suppression, got %+v", r.ID(), v, f)
			}
		}
	}
}

func TestCFG041to044_DenyAllStar_OldVersionStillFlags(t *testing.T) {
	rules := []Rule{CFG041, CFG042, CFG043, CFG044}
	// On < 2.1.166 the bare "*" is a no-op, so the deny block does not cover the
	// sensitive classes and the findings must still fire.
	tgt := denyTarget(t, `"*"`, ver(2, 1, 165))
	for _, r := range rules {
		if f := r.Check(tgt); len(f) != 1 {
			t.Errorf("%s with deny [\"*\"] at 2.1.165: expected 1 finding (deny-all ineffective), got %+v", r.ID(), f)
		}
	}
}

func TestIgnoresParamForm(t *testing.T) {
	cases := []struct {
		entry string
		want  bool
	}{
		// Canonicalized fields Claude Code ignores in the param:value form.
		{"Read(file_path:.env)", true},
		{"Edit(file_path:secrets/**)", true},
		{"Write(file_path:.env)", true},
		{"Bash(command:rm *)", true},
		{"PowerShell(command:Remove-Item *)", true},
		{"Grep(path:.env)", true},
		{"WebFetch(url:https://x)", true},
		{"NotebookEdit(notebook_path:x.ipynb)", true},
		{"Read( file_path : .env )", true}, // whitespace around colon ignored
		{"read(file_path:.env)", true},     // tool name case-insensitive
		// Tools' own valid specifiers / non-canonicalized params — NOT ignored.
		{"Read(.env)", false},
		{"Read(**/.env)", false},
		{"WebFetch(domain:example.com)", false},
		{"Agent(model:opus)", false},
		{"Bash(rm *)", false},
		{"Read(config:value.env)", false}, // 'config' is not Read's canonicalized field
		{"*", false},
		{"Read", false},
	}
	for _, c := range cases {
		if got := ignoresParamForm(c.entry); got != c.want {
			t.Errorf("ignoresParamForm(%q) = %v, want %v", c.entry, got, c.want)
		}
	}
}

func TestCFG041_IgnoredFilePathParamForm_StillFlags(t *testing.T) {
	// Read(file_path:.env) is the param:value form Claude Code ignores (file_path
	// is canonicalized), so it provides NO coverage — CFG041 must still fire even
	// though the ".env" substring is present in the entry.
	tgt := denyTarget(t, `"Read(file_path:.env)"`, ver(2, 2, 0))
	if f := CFG041.Check(tgt); len(f) != 1 {
		t.Errorf("expected CFG041 to fire on the ignored Read(file_path:.env) form, got %+v", f)
	}
	// The correct spelling still suppresses it.
	tgt = denyTarget(t, `"Read(**/.env)","Read(**/.env.*)"`, ver(2, 2, 0))
	if f := CFG041.Check(tgt); len(f) != 0 {
		t.Errorf("expected CFG041 suppressed by Read(**/.env), got %+v", f)
	}
}

func TestCFG041to044_ReadAllWildcard_Suppressed(t *testing.T) {
	rules := []Rule{CFG041, CFG042, CFG043, CFG044}
	// Read(**) blocks every read regardless of version.
	for _, pat := range []string{`"Read(*)"`, `"Read(**)"`, `"Read(**/*)"`} {
		tgt := denyTarget(t, pat, ver(2, 0, 0)) // old version: still suppressed (version-independent)
		for _, r := range rules {
			if f := r.Check(tgt); len(f) != 0 {
				t.Errorf("%s with deny [%s] at old version: expected suppression, got %+v", r.ID(), pat, f)
			}
		}
	}
}
