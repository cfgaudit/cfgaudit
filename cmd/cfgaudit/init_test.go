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
	if len(doc.Permissions.Deny) != len(baselineDeny) {
		t.Errorf("expected %d deny entries, got %d", len(baselineDeny), len(doc.Permissions.Deny))
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
