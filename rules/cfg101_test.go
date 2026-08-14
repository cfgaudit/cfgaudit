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

// One finding per file rather than per entry (#517). The rule reported on 44% of
// deny-carrying configs in the pre-release measurement, all of it genuine, and a
// file's entries are read and fixed together.
func TestCFG101_OneFindingPerList(t *testing.T) {
	f := CFG101.Check(settingsTarget(t, `{"permissions":{"deny":[
		"Bash(rm -rf *)","Bash(rm -rf /)","Bash(git clean -fdx:*)"]}}`))
	if len(f) != 1 {
		t.Fatalf("expected the three entries collapsed into one finding, got %d: %+v", len(f), f)
	}
	for _, want := range []string{"has 3 entries", `"Bash(rm -rf *)"`, `"Bash(git clean -fdx:*)"`, `"Bash(rm *)"`, `"Bash(git *)"`} {
		if !strings.Contains(f[0].Message, want) {
			t.Errorf("message should contain %q, got %q", want, f[0].Message)
		}
	}
}

// deny and ask are separate guarantees, so they stay separate findings even
// though both are collapsed within themselves.
func TestCFG101_DenyAndAskStaySeparate(t *testing.T) {
	f := CFG101.Check(settingsTarget(t, `{"permissions":{
		"deny":["Bash(rm -rf *)","Bash(rm -rf /)"],
		"ask":["Bash(tar -xzf *)"]}}`))
	if len(f) != 2 {
		t.Fatalf("expected one finding per list, got %d: %+v", len(f), f)
	}
	if !strings.Contains(f[0].Message, "permissions.deny has 2 entries") {
		t.Errorf("expected the deny list collapsed, got %q", f[0].Message)
	}
	if !strings.Contains(f[1].Message, "permissions.ask entry") {
		t.Errorf("expected the single ask entry in singular form, got %q", f[1].Message)
	}
}

// A long deny list must not produce an unreadable finding: the entries are capped
// and what was dropped is named, so the count and the list never disagree.
func TestCFG101_LongListCapped(t *testing.T) {
	got := onlyFinding(t, CFG101.Check(settingsTarget(t, `{"permissions":{"deny":[
		"Bash(rm -rf *)","Bash(git clean -fdx:*)","Bash(tar -xzf *)",
		"Bash(docker system prune -af:*)","Bash(curl -sk *)","Bash(unzip -qq *)"]}}`)), finding.Warn)
	if !strings.Contains(got.Message, "has 6 entries") {
		t.Errorf("expected the full count, got %q", got.Message)
	}
	if !strings.Contains(got.Message, "and 2 more") {
		t.Errorf("expected the dropped entries named, got %q", got.Message)
	}
	if strings.Contains(got.Message, "Bash(unzip -qq *)") {
		t.Errorf("expected the list capped at four entries, got %q", got.Message)
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
