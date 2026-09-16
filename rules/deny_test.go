package rules

import (
	"fmt"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/version"
)

func ver(major, minor, patch int) *version.Version {
	return &version.Version{Major: major, Minor: minor, Patch: patch}
}

// denyReadsCovered is exercised against the .env class (CFG041), covering the
// grant paths (deny-all "*", Read-all wildcards, a class-covering Read deny), the
// version gate on the bare "*", and the Read(!glob) exception carve (#581).
func TestDenyReadsCovered(t *testing.T) {
	cases := []struct {
		name string
		deny []string
		ver  *version.Version
		want bool
	}{
		// bare "*" deny-all glob — version-gated on 2.1.166
		{"star unknown version", []string{"*"}, nil, true},
		{"star at min version", []string{"*"}, ver(2, 1, 166), true},
		{"star just below min version", []string{"*"}, ver(2, 1, 165), false},

		// Read-all wildcards — version-independent
		{"Read(*) old version", []string{"Read(*)"}, ver(1, 0, 0), true},
		{"Read(**) unknown version", []string{"Read(**)"}, nil, true},
		{"Read with whitespace", []string{" Read(**) "}, ver(2, 1, 100), true},

		// a class-covering Read deny
		{"specific env read covers env", []string{"Read(**/.env)"}, ver(2, 2, 0), true},

		// no coverage
		{"bash wildcard covers nothing", []string{"Bash(rm -rf *)"}, ver(2, 2, 0), false},
		{"edit star is not a read", []string{"Edit(*)"}, ver(2, 2, 0), false},
		{"empty deny", nil, ver(2, 2, 0), false},

		// exception carves the class out of an earlier grant
		{"read-all then env exception", []string{"Read(**)", "Read(!**/.env)"}, nil, false},
		{"star then env exception", []string{"*", "Read(!**/.env)"}, nil, false},
		{"edit exception carves too", []string{"Read(**)", "Edit(!**/.env)"}, nil, false},
		{"deny then exception", []string{"Read(**/.env)", "Read(!**/.env)"}, ver(2, 2, 0), false},
		{"lone exception grants nothing", []string{"Read(!**/.env)"}, ver(2, 2, 0), false},

		// exception ordered before the deny removes nothing from it
		{"exception before deny", []string{"Read(!**/.env)", "Read(**/.env)"}, ver(2, 2, 0), true},

		// narrow / unrelated exceptions do not carve the .env class
		{"example carve keeps env", []string{"Read(**/.env*)", "Read(!**/.env.example)"}, ver(2, 2, 0), true},
		{"read-all with example carve", []string{"Read(**)", "Read(!**/.env.example)"}, nil, true},
		{"read-all with log carve", []string{"Read(**)", "Read(!*.log)"}, nil, true},
		{"read-all with pem carve keeps env", []string{"Read(**)", "Read(!**/*.pem)"}, nil, true},
	}
	for _, c := range cases {
		if got := denyReadsCovered(c.deny, envCoverRe, envSecretPaths, c.ver); got != c.want {
			t.Errorf("%s: denyReadsCovered(%v, %v) = %v, want %v", c.name, c.deny, c.ver, got, c.want)
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

func TestReadDenyPattern(t *testing.T) {
	cases := []struct {
		entry   string
		wantPat string
		wantOK  bool
	}{
		// Read specifier forms — these DO provide read coverage.
		{"Read(**/.env)", "**/.env", true},
		{"Read(.env)", ".env", true},
		{" read(~/.ssh/*) ", "~/.ssh/*", true}, // trimmed + case-insensitive tool
		// Non-Read tools do not block the Read tool → no coverage.
		{"Write(**/.env)", "", false},
		{"NotebookEdit(**/.env)", "", false},
		{"Glob(**/.env)", "", false},
		{"Grep(**/.env)", "", false},
		{"Edit(**/.env)", "", false},
		{"Bash(rm -rf *)", "", false},
		// Read(param:value) on the canonicalized field is ignored by Claude Code.
		{"Read(file_path:.env)", "", false},
		// Bare tool name / non-permission entries have no path glob.
		{"Read", "", false},
		{"*", "", false},
	}
	for _, c := range cases {
		gotPat, gotOK := readDenyPattern(c.entry)
		if gotOK != c.wantOK || gotPat != c.wantPat {
			t.Errorf("readDenyPattern(%q) = (%q, %v), want (%q, %v)", c.entry, gotPat, gotOK, c.wantPat, c.wantOK)
		}
	}
}

func TestCFG041to044_NonReadDeny_ProvidesNoCoverage(t *testing.T) {
	// A Write/NotebookEdit/Glob specifier form is ignored by Claude Code
	// (>= 2.1.210); Edit/Grep denies don't block the Read tool. None of these
	// cover a read of the sensitive file, so the findings must still fire. Each
	// rule gets an entry spelling its own class so only the tool name differs.
	cases := []struct {
		rule Rule
		deny string // a single deny entry, wrapped by the loop below
	}{
		{CFG041, `%s(**/.env)`},
		{CFG042, `%s(**/*.pem)`},
		{CFG043, `%s(**/.aws/credentials)`},
		{CFG044, `%s(**/.ssh/**)`},
	}
	for _, tool := range []string{"Write", "NotebookEdit", "Glob", "Grep", "Edit"} {
		for _, c := range cases {
			entry := `"` + fmt.Sprintf(c.deny, tool) + `"`
			tgt := denyTarget(t, entry, ver(2, 2, 0))
			if f := c.rule.Check(tgt); len(f) != 1 {
				t.Errorf("%s with deny [%s]: expected 1 finding (no read coverage), got %+v", c.rule.ID(), entry, f)
			}
		}
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

// #581: a Read(!glob) / Edit(!glob) exception removes paths from the deny rules
// before it, so a deny-all with the credential files carved out must not suppress
// CFG041–044 for the carved classes.
func TestCFG041to044_ReadException_Uncovers(t *testing.T) {
	// A deny-all read plus exceptions for exactly .env and *.pem: CFG041 (.env)
	// and CFG042 (*.pem) fire, while CFG043 (cloud) and CFG044 (ssh) stay quiet
	// because Read(**) still denies them.
	tgt := denyTarget(t, `"Read(**)", "Read(!**/.env)", "Read(!**/*.pem)"`, ver(2, 2, 0))
	fired := map[string]bool{}
	for _, r := range []Rule{CFG041, CFG042, CFG043, CFG044} {
		if len(r.Check(tgt)) > 0 {
			fired[r.ID()] = true
		}
	}
	if !fired["CFG041"] {
		t.Error("CFG041 must fire: .env is carved out of the deny-all")
	}
	if !fired["CFG042"] {
		t.Error("CFG042 must fire: *.pem is carved out of the deny-all")
	}
	if fired["CFG043"] || fired["CFG044"] {
		t.Errorf("CFG043/CFG044 must stay quiet: nothing carves cloud/ssh, got %v", fired)
	}
}

func TestCFG041_LoneEnvException_Fires(t *testing.T) {
	// A single Read(!**/.env) denies nothing, so .env is unprotected.
	tgt := denyTarget(t, `"Read(!**/.env)"`, ver(2, 2, 0))
	if f := CFG041.Check(tgt); len(f) != 1 {
		t.Errorf("expected CFG041 to fire on a lone .env exception, got %+v", f)
	}
}

// The control from the corpus: a .env* deny with a .env.example exception. The
// exception re-allows only the template, so .env is still denied and CFG041 must
// stay quiet — no regression on the real files.
func TestCFG041_EnvExampleException_NoChange(t *testing.T) {
	tgt := denyTarget(t, `"Read(**/.env*)", "Read(!**/.env.example)"`, ver(2, 2, 0))
	if f := CFG041.Check(tgt); len(f) != 0 {
		t.Errorf("a .env.example carve must not un-cover .env, got %+v", f)
	}
}
