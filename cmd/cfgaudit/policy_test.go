package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyGenerate_MergesIntoConfig(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude", "settings.json"),
		`{"permissions":{"deny":["Bash(rm -rf *)","Read(**/.env)"]}}`)
	mustWrite(t, filepath.Join(dir, ".cfgaudit.yml"),
		"# project policy\npolicy:\n  require-deny:\n    - \"Bash(rm -rf *)\"\n")

	out, code := policyOutput([]string{"generate", dir})
	if code != 0 || !strings.Contains(out, "Read(**/.env)") {
		t.Fatalf("expected Read(**/.env) added, got code=%d out=%s", code, out)
	}
	got, _ := os.ReadFile(filepath.Join(dir, ".cfgaudit.yml")) // #nosec G304 -- test temp path
	s := string(got)
	if !strings.Contains(s, "# project policy") {
		t.Errorf("expected leading comment preserved, got:\n%s", s)
	}
	if !strings.Contains(s, "Read(**/.env)") || !strings.Contains(s, "Bash(rm -rf *)") {
		t.Errorf("expected both deny entries in require-deny, got:\n%s", s)
	}
}

func TestPolicyGenerate_NewConfigFile(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude", "settings.json"),
		`{"permissions":{"deny":["Bash(sudo *)"]}}`)
	if _, code := policyOutput([]string{"generate", dir}); code != 0 {
		t.Fatalf("expected success, got code %d", code)
	}
	got, err := os.ReadFile(filepath.Join(dir, ".cfgaudit.yml")) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("expected .cfgaudit.yml created: %v", err)
	}
	if !strings.Contains(string(got), "Bash(sudo *)") {
		t.Errorf("expected entry in new config, got:\n%s", got)
	}
}

func TestPolicyGenerate_NoDeny(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude", "settings.json"), `{"permissions":{"allow":["Bash(make *)"]}}`)
	out, code := policyOutput([]string{"generate", dir})
	if code != 0 || !strings.Contains(out, "nothing to do") {
		t.Errorf("expected nothing-to-do, got code=%d out=%s", code, out)
	}
}

func TestPolicyApply_DryRunDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, ".claude", "settings.json")
	mustWrite(t, settings, `{"permissions":{"deny":["Read(**/.env)"]}}`)
	mustWrite(t, filepath.Join(dir, ".cfgaudit.yml"),
		"policy:\n  require-deny:\n    - \"Bash(git push --force*)\"\n    - \"Read(**/.env)\"\n")

	before, _ := os.ReadFile(settings) // #nosec G304 -- test temp path
	out, code := policyOutput([]string{"apply", "--dry-run", dir})
	after, _ := os.ReadFile(settings) // #nosec G304 -- test temp path
	if code != 0 || !strings.Contains(out, "would add") || !strings.Contains(out, "Bash(git push --force*)") {
		t.Fatalf("unexpected dry-run output: code=%d out=%s", code, out)
	}
	if string(before) != string(after) {
		t.Error("dry-run must not modify settings.json")
	}
}

func TestPolicyApply_WritesMissingAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, ".claude", "settings.json")
	mustWrite(t, settings, `{"permissions":{"deny":["Read(**/.env)"]}}`)
	mustWrite(t, filepath.Join(dir, ".cfgaudit.yml"),
		"policy:\n  require-deny:\n    - \"Bash(git push --force*)\"\n")

	if _, code := policyOutput([]string{"apply", dir}); code != 0 {
		t.Fatalf("apply failed: %d", code)
	}
	got, _ := os.ReadFile(settings) // #nosec G304 -- test temp path
	if !strings.Contains(string(got), "Bash(git push --force*)") || !strings.Contains(string(got), "Read(**/.env)") {
		t.Errorf("expected both deny entries after apply, got:\n%s", got)
	}
	// second apply is a no-op
	out, code := policyOutput([]string{"apply", dir})
	if code != 0 || !strings.Contains(out, "already satisfies") {
		t.Errorf("expected idempotent no-op, got code=%d out=%s", code, out)
	}
}

func TestPolicy_UsageAndUnknown(t *testing.T) {
	if _, code := policyOutput(nil); code != 2 {
		t.Error("expected usage exit 2 for no args")
	}
	if _, code := policyOutput([]string{"frobnicate"}); code != 2 {
		t.Error("expected exit 2 for unknown subcommand")
	}
}
