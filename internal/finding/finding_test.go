package finding

import "testing"

func TestFindingString(t *testing.T) {
	withLine := Finding{RuleID: "CFG001", Severity: Error, File: "a.json", Line: 3, Col: 7, Message: "m"}
	if got, want := withLine.String(), "a.json:3:7 [error] CFG001: m"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	noLine := Finding{RuleID: "CFG002", Severity: Warn, File: "b.json", Message: "m"}
	if got, want := noLine.String(), "b.json [warn] CFG002: m"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if Info.String() != "info" {
		t.Errorf("Info.String() = %q", Info.String())
	}
}
