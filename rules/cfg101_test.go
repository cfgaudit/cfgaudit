package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// The measured defect (#480): with Bash(echo -n *) denied, `echo -e -n x` and
// `echo x -n` both ran. A bundled flag is the shape where the evasion needs no
// thought at all: rm -rf never covered rm -fr.
func TestCFG101_BundledFlagReported(t *testing.T) {
	got := onlyFinding(t, CFG101.Check(settingsTarget(t,
		`{"permissions":{"deny":["Bash(rm -rf *)"]}}`)), finding.Warn)
	for _, want := range []string{"-rf", "-fr", "Bash(rm *)", "literal prefix"} {
		if !strings.Contains(got.Message, want) {
			t.Errorf("message should contain %q, got %q", want, got.Message)
		}
	}
}

// The colon spelling is the same rule.
func TestCFG101_ColonSpelling(t *testing.T) {
	onlyFinding(t, CFG101.Check(settingsTarget(t,
		`{"permissions":{"deny":["Bash(rm -rf:*)"]}}`)), finding.Warn)
}

// An ask rule that fails to match is a prompt that does not happen.
func TestCFG101_AskRules(t *testing.T) {
	got := onlyFinding(t, CFG101.Check(settingsTarget(t,
		`{"permissions":{"ask":["Bash(docker -it run *)"]}}`)), finding.Warn)
	if !strings.Contains(got.Message, "permissions.ask") {
		t.Errorf("expected the list named, got %q", got.Message)
	}
}

// The shapes deliberately left alone, each because something real would
// otherwise be misread.
func TestCFG101_NotReported(t *testing.T) {
	for _, body := range []string{
		`{"permissions":{"deny":["Bash(rm *)"]}}`,                       // no flags at all
		`{"permissions":{"deny":["Bash(git push --force*)"]}}`,          // a long flag cannot be permuted
		`{"permissions":{"deny":["Bash(git push -f*)"]}}`,               // a lone short flag has nothing to permute
		`{"permissions":{"deny":["Bash(find -name *)"]}}`,               // single-dash LONG option, not a bundle
		`{"permissions":{"deny":["Bash(find -type f *)"]}}`,             // same
		`{"permissions":{"deny":["Bash(java -version)"]}}`,              // same
		`{"permissions":{"deny":["Bash(npm run test:*)"]}}`,             // subcommands are not flags
		`{"permissions":{"deny":["PowerShell(Remove-Item -Recurse)"]}}`, // PowerShell does not bundle
		`{"permissions":{"deny":["Bash(*)"]}}`,                          // a catch-all constrains nothing
		`{"permissions":{"deny":["Read(//**/.ssh/**)"]}}`,               // not a command rule
		`{"permissions":{"allow":["Bash(rm -rf *)"]}}`,                  // an allow that misses is a prompt
	} {
		if f := CFG101.Check(settingsTarget(t, body)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", body, f)
		}
	}
}

// A file that also denies the bare command has closed the gap; the narrower
// entry beside it is redundant rather than a hole.
func TestCFG101_BareDenialSuppresses(t *testing.T) {
	for _, body := range []string{
		`{"permissions":{"deny":["Bash(rm -rf *)","Bash(rm *)"]}}`,
		`{"permissions":{"deny":["Bash(rm -rf:*)","Bash(rm:*)"]}}`,
	} {
		if f := CFG101.Check(settingsTarget(t, body)); len(f) != 0 {
			t.Errorf("expected no finding for %s, got %+v", body, f)
		}
	}
	// A bare denial of a DIFFERENT command does not cover this one.
	onlyFinding(t, CFG101.Check(settingsTarget(t,
		`{"permissions":{"deny":["Bash(rm -rf *)","Bash(curl *)"]}}`)), finding.Warn)
}

// Several bundles in one entry are named together, in a stable order.
func TestCFG101_MultipleFlags(t *testing.T) {
	got := onlyFinding(t, CFG101.Check(settingsTarget(t,
		`{"permissions":{"deny":["Bash(tar -xzf -it *)"]}}`)), finding.Warn)
	if !strings.Contains(got.Message, `"-it", "-xzf"`) {
		t.Errorf("expected both flags in a stable order, got %q", got.Message)
	}
}

func TestCFG101_NoPermissions(t *testing.T) {
	if f := CFG101.Check(settingsTarget(t, `{}`)); len(f) != 0 {
		t.Errorf("expected no findings, got %+v", f)
	}
	if f := CFG101.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no findings without settings, got %+v", f)
	}
}
