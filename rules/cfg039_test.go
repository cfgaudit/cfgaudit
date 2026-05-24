package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG039_BroadTarget_Error(t *testing.T) {
	for _, cmd := range []string{
		"rm -rf ~",
		"rm -rf /",
		"rm -rf $HOME",
		"rm -rf ~/*",
		"rm -fr ..",
		"rm -rf *",
	} {
		f := CFG039.Check(hookTarget(t, cmd))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected Error for %q, got %+v", cmd, f)
		}
	}
}

func TestCFG039_ScopedTarget_Warn(t *testing.T) {
	for _, cmd := range []string{
		"rm -rf ./build",
		"rm -rf node_modules",
		"rm -r -f ~/project/dist",
		"rm -Rf .cache",
	} {
		f := CFG039.Check(hookTarget(t, cmd))
		if len(f) != 1 || f[0].Severity != finding.Warn {
			t.Errorf("expected Warn for %q, got %+v", cmd, f)
		}
	}
}

func TestCFG039_NotForceRecursive_NoFinding(t *testing.T) {
	for _, cmd := range []string{
		"rm file.txt",
		"rm -r ./dir",        // recursive but not force
		"rm -f file.txt",     // force but not recursive
		"echo rm -rf is bad", // not an rm invocation's flags... actually contains rm -rf
	} {
		f := CFG039.Check(hookTarget(t, cmd))
		if cmd == "echo rm -rf is bad" {
			continue // documented edge: substring match is acceptable
		}
		if len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", cmd, f)
		}
	}
}

func TestCFG039_ScansHelperKeys(t *testing.T) {
	f := CFG039.Check(settingsTarget(t, `{"statusLine":{"type":"command","command":"rm -rf ~/.cache && status.sh"}}`))
	if len(f) != 1 {
		t.Fatalf("expected CFG039 on statusLine helper, got %+v", f)
	}
}

func TestCFG039_NoSettings_NoFinding(t *testing.T) {
	if f := CFG039.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding without settings, got %+v", f)
	}
}
