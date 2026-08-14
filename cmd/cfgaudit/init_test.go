package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/rules"
)

func ruleByID(id string) rules.Rule {
	for _, r := range rules.All {
		if r.ID() == id {
			return r
		}
	}
	return nil
}

func TestInit_WritesBaselineAndScansClean(t *testing.T) {
	dir := t.TempDir()
	out, code := initOutput([]string{dir}, strings.NewReader(""))
	if code != 0 || !strings.Contains(out, "wrote") {
		t.Fatalf("init failed: code=%d out=%s", code, out)
	}
	path := filepath.Join(dir, ".claude", "settings.json")
	data, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("expected settings.json written: %v", err)
	}
	var doc struct {
		Permissions struct {
			Deny []string `json:"deny"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON written: %v", err)
	}
	if len(doc.Permissions.Deny) != len(standardDeny) {
		t.Errorf("expected %d deny entries, got %d", len(standardDeny), len(doc.Permissions.Deny))
	}

	// The whole point: the generated file passes the deny-coverage rules.
	targets, err := buildTargets(dir, false)
	if err != nil {
		t.Fatalf("buildTargets: %v", err)
	}
	for _, id := range []string{"CFG006", "CFG041", "CFG042", "CFG043", "CFG044"} {
		for _, tg := range targets {
			if f := ruleByID(id).Check(tg); len(f) != 0 {
				t.Errorf("%s should not fire on the init baseline, got %+v", id, f)
			}
		}
	}
}

func TestInit_AbortsIfExists(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude", "settings.json"), `{}`)
	if _, code := initOutput([]string{dir}, strings.NewReader("")); code != 1 {
		t.Errorf("expected exit 1 when file exists, got %d", code)
	}
	if _, code := initOutput([]string{"--force", dir}, strings.NewReader("")); code != 0 {
		t.Errorf("expected --force to overwrite, got %d", code)
	}
}

func TestInit_DryRunDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	out, code := initOutput([]string{"--dry-run", dir}, strings.NewReader(""))
	if code != 0 || !strings.Contains(out, "\"permissions\"") {
		t.Fatalf("expected JSON to stdout, got code=%d out=%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, ".claude", "settings.json")); err == nil {
		t.Error("--dry-run must not write the file")
	}
}

func TestInit_Interactive(t *testing.T) {
	dir := t.TempDir()
	// add one new entry and one duplicate of the baseline; blank line ends input
	stdin := strings.NewReader("Bash(kubectl:*)\nBash(rm -rf *)\n\n")
	if _, code := initOutput([]string{"--interactive", dir}, stdin); code != 0 {
		t.Fatalf("interactive init failed: %d", code)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ".claude", "settings.json")) // #nosec G304 -- test temp path
	s := string(data)
	if !strings.Contains(s, "kubectl") {
		t.Error("expected the added entry in the deny list")
	}
	if strings.Count(s, "rm -rf") != 1 {
		t.Error("baseline duplicate should not be added twice")
	}
}

func TestInit_UnknownFlag(t *testing.T) {
	if _, code := initOutput([]string{"--nope"}, strings.NewReader("")); code != 2 {
		t.Errorf("expected exit 2 for unknown flag, got %d", code)
	}
}

// #481: every profile must produce a file that cfgaudit itself passes. A
// scaffold that trips the tool it ships with is worse than no scaffold.
func TestInit_EveryProfileScansClean(t *testing.T) {
	for _, profile := range profileNames() {
		t.Run(profile, func(t *testing.T) {
			dir := t.TempDir()
			out, code := initOutput([]string{"--profile", profile, dir}, strings.NewReader(""))
			if code != 0 || !strings.Contains(out, "profile: "+profile) {
				t.Fatalf("init failed: code=%d out=%s", code, out)
			}
			targets, err := buildTargets(dir, false)
			if err != nil {
				t.Fatalf("buildTargets: %v", err)
			}
			for _, r := range rules.All {
				for _, tg := range targets {
					if f := r.Check(tg); len(f) != 0 {
						t.Errorf("%s fired on the %s profile: %+v", r.ID(), profile, f)
					}
				}
			}
		})
	}
}

// The profiles are nested, so a step up never drops protection.
func TestInit_ProfilesAreSupersets(t *testing.T) {
	has := func(list []string) map[string]bool {
		m := map[string]bool{}
		for _, e := range list {
			m[e] = true
		}
		return m
	}
	std, par := has(standardDeny), has(paranoidDeny)
	for _, e := range minimalDeny {
		if !std[e] {
			t.Errorf("standard drops the minimal entry %q", e)
		}
	}
	for _, e := range standardDeny {
		if !par[e] {
			t.Errorf("paranoid drops the standard entry %q", e)
		}
	}
	if len(minimalDeny) >= len(standardDeny) || len(standardDeny) >= len(paranoidDeny) {
		t.Errorf("profiles must grow: %d / %d / %d", len(minimalDeny), len(standardDeny), len(paranoidDeny))
	}
}

// No profile may contain a duplicate: the file is meant to be read.
func TestInit_ProfilesHaveNoDuplicates(t *testing.T) {
	for _, profile := range profileNames() {
		seen := map[string]bool{}
		for _, e := range denyProfiles[profile] {
			if seen[e] {
				t.Errorf("%s repeats %q", profile, e)
			}
			seen[e] = true
		}
	}
}

func TestInit_ProfileFlagForms(t *testing.T) {
	for _, args := range [][]string{{"--profile", "minimal"}, {"--profile=minimal"}} {
		dir := t.TempDir()
		out, code := initOutput(append(args, dir), strings.NewReader(""))
		if code != 0 || !strings.Contains(out, "profile: minimal") {
			t.Errorf("%v: code=%d out=%s", args, code, out)
		}
	}
}

func TestInit_UnknownProfileAndMissingValue(t *testing.T) {
	for _, args := range [][]string{{"--profile", "nonsense"}, {"--profile=nonsense"}, {"--profile"}} {
		out, code := initOutput(args, strings.NewReader(""))
		if code != 2 {
			t.Errorf("%v: expected exit 2, got %d (%s)", args, code, out)
		}
	}
}

// The default has to stay a superset of what init wrote before profiles existed,
// so an existing user does not quietly get a weaker file.
func TestInit_DefaultProfileIsStandard(t *testing.T) {
	dir := t.TempDir()
	out, _ := initOutput([]string{dir}, strings.NewReader(""))
	if !strings.Contains(out, "profile: standard") {
		t.Errorf("expected standard by default, got %s", out)
	}
	for _, e := range []string{"Read(//**/.ssh/**)", "Bash(rm *)", "Bash(git push --force*)"} {
		found := false
		for _, d := range standardDeny {
			if d == e {
				found = true
			}
		}
		if !found {
			t.Errorf("standard must still contain the pre-profile entry %q", e)
		}
	}
}
