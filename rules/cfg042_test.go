package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG042_DenyMissingKeys(t *testing.T) {
	f := CFG042.Check(settingsTarget(t, `{"permissions":{"deny":["Read(.env)"]}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
	for _, ext := range []string{"*.pem", "*.key", "*.p12", "*.pfx", "*.jks"} {
		if !strings.Contains(f[0].Message, ext) {
			t.Errorf("expected message to list %s, got: %s", ext, f[0].Message)
		}
	}
}

func TestCFG042_PartialCoverage(t *testing.T) {
	f := CFG042.Check(settingsTarget(t, `{"permissions":{"deny":["Read(**/*.pem)","Read(**/*.key)"]}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for partial coverage, got %+v", f)
	}
	if strings.Contains(f[0].Message, "*.pem") || strings.Contains(f[0].Message, "*.key") {
		t.Errorf("covered extensions should not be listed, got: %s", f[0].Message)
	}
	for _, ext := range []string{"*.p12", "*.pfx", "*.jks"} {
		if !strings.Contains(f[0].Message, ext) {
			t.Errorf("expected remaining gap %s listed, got: %s", ext, f[0].Message)
		}
	}
}

func TestCFG042_FullCoverage_NoFinding(t *testing.T) {
	json := `{"permissions":{"deny":["Read(**/*.pem)","Read(**/*.key)","Read(**/*.p12)","Read(**/*.pfx)","Read(**/*.jks)"]}}`
	if f := CFG042.Check(settingsTarget(t, json)); len(f) != 0 {
		t.Errorf("expected no finding with full coverage, got %+v", f)
	}
}

func TestCFG042_NoDenyBlock_NoFinding(t *testing.T) {
	if f := CFG042.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"]}}`)); len(f) != 0 {
		t.Errorf("expected no finding when deny absent, got %+v", f)
	}
}
