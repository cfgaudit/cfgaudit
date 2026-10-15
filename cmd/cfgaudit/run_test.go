package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runFixture writes files (path relative to a fresh scan root -> content) and
// returns the root. HOME points at an empty directory so no user-scope file on
// the machine running the tests can leak into a scan.
func runFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	setHome(t, t.TempDir())
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// runCLI runs the CLI with args after the program name. --claude-version is
// prepended to scans by the callers that need it, so no test runs the real
// `claude --version`.
func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(append([]string{"cfgaudit"}, args...), strings.NewReader(""), &out, &errOut)
	return code, out.String(), errOut.String()
}

const (
	// CFG004 (error) and CFG006 (warn).
	errorSettings = `{"permissions":{"defaultMode":"bypassPermissions"}}`
	// CFG006 and CFG040, both warn.
	warnSettings = `{"permissions":{"allow":["WebFetch"]}}`
)

func TestRun_ExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		settings string // .claude/settings.json; empty means no file
		config   string // .cfgaudit.yml; empty means no file
		args     []string
		want     int
	}{
		{name: "no config files", want: 0},
		{name: "error finding", settings: errorSettings, want: 1},
		{name: "warn findings only", settings: warnSettings, want: 0},
		{name: "warn findings with --strict", settings: warnSettings, args: []string{"--strict"}, want: 1},
		{name: "warn findings with strict in .cfgaudit.yml", settings: warnSettings, config: "strict: true\n", want: 1},
		{name: "error rule skipped", settings: errorSettings, args: []string{"--skip", "CFG004"}, want: 0},
		{name: "only a warn rule", settings: errorSettings, args: []string{"--only", "CFG006"}, want: 0},
		{name: "no-exit-codes in .cfgaudit.yml", settings: errorSettings, config: "no-exit-codes: true\n", want: 0},
		{name: "rule turned off in .cfgaudit.yml", settings: errorSettings, config: "rules:\n  CFG004: off\n", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{}
			if tt.settings != "" {
				files[".claude/settings.json"] = tt.settings
			}
			if tt.config != "" {
				files[".cfgaudit.yml"] = tt.config
			}
			root := runFixture(t, files)
			args := append([]string{"--claude-version", "2.1.0", "--format", "text"}, tt.args...)
			code, stdout, stderr := runCLI(t, append(args, root)...)
			if code != tt.want {
				t.Errorf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.want, stdout, stderr)
			}
		})
	}
}

func TestRun_TextOutputListsFindingsAndCount(t *testing.T) {
	root := runFixture(t, map[string]string{".claude/settings.json": errorSettings})
	_, stdout, _ := runCLI(t, "--claude-version", "2.1.0", "--format", "text", root)
	for _, want := range []string{"CFG004", "CFG006", "cfgaudit dev — 2 findings"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("text output lacks %q:\n%s", want, stdout)
		}
	}
}

func TestRun_Formats(t *testing.T) {
	root := runFixture(t, map[string]string{".claude/settings.json": errorSettings})
	scan := func(format string) string {
		t.Helper()
		code, stdout, stderr := runCLI(t, "--claude-version", "2.1.0", "--format", format, root)
		if code != 1 {
			t.Fatalf("--format %s: exit code %d, want 1\nstderr:\n%s", format, code, stderr)
		}
		return stdout
	}

	var findings []struct{ RuleID, Severity string }
	if err := json.Unmarshal([]byte(scan("json")), &findings); err != nil {
		t.Fatalf("json output does not parse: %v", err)
	}
	if len(findings) != 2 || findings[0].RuleID != "CFG004" || findings[0].Severity != "error" {
		t.Errorf("json findings = %+v, want CFG004 (error) first of two", findings)
	}

	var sarif struct {
		Version string
		Runs    []struct {
			Results []struct{ RuleID string }
		}
	}
	if err := json.Unmarshal([]byte(scan("sarif")), &sarif); err != nil {
		t.Fatalf("sarif output does not parse: %v", err)
	}
	if sarif.Version != "2.1.0" || len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 2 {
		t.Errorf("sarif = version %q with %d runs, want 2.1.0 with one run of two results", sarif.Version, len(sarif.Runs))
	}

	for _, format := range []string{"codeclimate", "codequality"} {
		var issues []struct {
			CheckName string `json:"check_name"`
		}
		if err := json.Unmarshal([]byte(scan(format)), &issues); err != nil {
			t.Fatalf("%s output does not parse: %v", format, err)
		}
		if len(issues) != 2 {
			t.Errorf("%s: %d issues, want 2", format, len(issues))
		}
	}

	if out := scan("table"); !strings.Contains(out, "SEVERITY") || !strings.Contains(out, "CFG004") {
		t.Errorf("table output lacks the header or CFG004:\n%s", out)
	}

	// auto is a table on a terminal and plain text otherwise; a buffer is
	// not a terminal.
	if out := scan("auto"); strings.Contains(out, "SEVERITY") || !strings.Contains(out, "2 findings") {
		t.Errorf("auto on a non-terminal is not the text format:\n%s", out)
	}
	// An unrecognised format falls back to text rather than failing.
	if out := scan("yaml"); !strings.Contains(out, "2 findings") {
		t.Errorf("unknown format did not fall back to text:\n%s", out)
	}
}

func TestRun_Version(t *testing.T) {
	code, stdout, _ := runCLI(t, "--version")
	if code != 0 || stdout != "cfgaudit dev\n" {
		t.Errorf("--version = (%d, %q), want (0, %q)", code, stdout, "cfgaudit dev\n")
	}
}

func TestRun_FlagErrors(t *testing.T) {
	code, _, stderr := runCLI(t, "--no-such-flag")
	if code != 2 || !strings.Contains(stderr, "no-such-flag") {
		t.Errorf("unknown flag = (%d, %q), want exit 2 naming the flag", code, stderr)
	}
	code, _, stderr = runCLI(t, "-h")
	if code != 0 || !strings.Contains(stderr, "-format") {
		t.Errorf("-h = (%d, %q), want exit 0 with the usage", code, stderr)
	}
}

func TestRun_ConfigErrors(t *testing.T) {
	root := runFixture(t, map[string]string{".claude/settings.json": warnSettings})
	code, _, stderr := runCLI(t, "--claude-version", "2.1.0", "--config", filepath.Join(root, "missing.yml"), root)
	if code != 2 || !strings.Contains(stderr, "missing.yml") {
		t.Errorf("missing --config = (%d, %q), want exit 2 naming the file", code, stderr)
	}

	bad := runFixture(t, map[string]string{".cfgaudit.yml": "strict: [not, a, bool\n"})
	code, _, stderr = runCLI(t, "--claude-version", "2.1.0", bad)
	if code != 2 || stderr == "" {
		t.Errorf("unparseable .cfgaudit.yml = (%d, %q), want exit 2 with an error", code, stderr)
	}

	good := runFixture(t, map[string]string{".cfgaudit.yml": "strict: false\n"})
	_, _, stderr = runCLI(t, "--claude-version", "2.1.0", good)
	if !strings.Contains(stderr, "using config") {
		t.Errorf("an auto-discovered config is not announced on stderr: %q", stderr)
	}
}

func TestRun_UnknownRuleIDIsReportedNotFatal(t *testing.T) {
	root := runFixture(t, map[string]string{".claude/settings.json": errorSettings})
	code, _, stderr := runCLI(t, "--claude-version", "2.1.0", "--skip", "CFG999", root)
	if !strings.Contains(stderr, "unknown rule(s): CFG999") {
		t.Errorf("unknown --skip id not reported: %q", stderr)
	}
	if code != 1 {
		t.Errorf("exit code %d, want 1: an unknown id must not stop the scan", code)
	}
}

func TestRun_Subcommands(t *testing.T) {
	code, stdout, _ := runCLI(t, "explain", "CFG004")
	if code != 0 || !strings.Contains(stdout, "CFG004") {
		t.Errorf("explain CFG004 = (%d, %.80q), want exit 0 with the rule doc", code, stdout)
	}
	if code, _, _ = runCLI(t, "explain", "CFG999"); code == 0 {
		t.Error("explain of an unknown rule exited 0")
	}
	code, stdout, _ = runCLI(t, "list")
	if code != 0 || !strings.Contains(stdout, "CFG001") {
		t.Errorf("list = (%d, %.80q), want exit 0 listing CFG001", code, stdout)
	}
	// policy without the arguments it needs is a usage error.
	if code, _, _ = runCLI(t, "policy"); code != 2 {
		t.Errorf("policy with no arguments exited %d, want 2", code)
	}
	// A subcommand name is only a subcommand in first position; after a flag
	// it is the scan directory.
	root := runFixture(t, nil)
	t.Chdir(root)
	_, stdout, _ = runCLI(t, "--claude-version", "2.1.0", "--format", "text", "list")
	if strings.Contains(stdout, "CFG001") || !strings.Contains(stdout, "0 findings") {
		t.Errorf("`list` after a flag was not scanned as a directory:\n%s", stdout)
	}
}
