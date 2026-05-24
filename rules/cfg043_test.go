package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG043_NoCloudCoverage(t *testing.T) {
	f := CFG043.Check(settingsTarget(t, `{"permissions":{"deny":["Read(.env)"]}}`))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
	for _, p := range []string{"AWS", "GCP", "Azure"} {
		if !strings.Contains(f[0].Message, p) {
			t.Errorf("expected %s listed as uncovered, got: %s", p, f[0].Message)
		}
	}
}

func TestCFG043_PartialCoverage(t *testing.T) {
	f := CFG043.Check(settingsTarget(t, `{"permissions":{"deny":["Read(**/.aws/credentials)"]}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if strings.Contains(f[0].Message, "AWS") {
		t.Errorf("AWS is covered and should not be listed: %s", f[0].Message)
	}
	if !strings.Contains(f[0].Message, "GCP") || !strings.Contains(f[0].Message, "Azure") {
		t.Errorf("expected GCP and Azure listed, got: %s", f[0].Message)
	}
}

func TestCFG043_BroadAwsCovers(t *testing.T) {
	// a broad ~/.aws/* counts for AWS
	f := CFG043.Check(settingsTarget(t, `{"permissions":{"deny":["Read(~/.aws/*)","Read(**/.config/gcloud/**)","Read(**/.azure/**)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding with all providers covered, got %+v", f)
	}
}

func TestCFG043_FullCoverage_NoFinding(t *testing.T) {
	json := `{"permissions":{"deny":["Read(**/.aws/credentials)","Read(**/application_default_credentials.json)","Read(**/.azure/**)"]}}`
	if f := CFG043.Check(settingsTarget(t, json)); len(f) != 0 {
		t.Errorf("expected no finding with full coverage, got %+v", f)
	}
}

func TestCFG043_NoDenyBlock_NoFinding(t *testing.T) {
	if f := CFG043.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"]}}`)); len(f) != 0 {
		t.Errorf("expected no finding when deny absent, got %+v", f)
	}
}
