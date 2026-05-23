package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func claudeMDTarget(content string) *Target {
	return &Target{
		Scope:           finding.ScopeProject,
		ClaudeMDFile:    "CLAUDE.md",
		ClaudeMDContent: content,
	}
}

func TestCFG024_TagsBlock(t *testing.T) {
	f := CFG024.Check(claudeMDTarget("docs" + string(rune(0xE0041)) + "hidden"))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for Tags-block char, got %+v", f)
	}
	if f[0].File != "CLAUDE.md" {
		t.Errorf("expected file CLAUDE.md, got %q", f[0].File)
	}
}

func TestCFG024_SuspiciousCodepoints(t *testing.T) {
	for _, cp := range []rune{0x200B, 0x200D, 0x200F, 0x202E, 0x2060, 0xFFF9} {
		f := CFG024.Check(claudeMDTarget("text" + string(cp) + "more"))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for U+%04X, got %+v", cp, f)
		}
	}
}

func TestCFG024_ReportsLineNumber(t *testing.T) {
	// suspicious char on the third line
	f := CFG024.Check(claudeMDTarget("line one\nline two\nhid" + string(rune(0x200B)) + "den\n"))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Line != 3 {
		t.Errorf("expected line 3, got %d", f[0].Line)
	}
}

func TestCFG024_LeadingBOM_Exempt(t *testing.T) {
	f := CFG024.Check(claudeMDTarget(string(rune(0xFEFF)) + "# Project memory\nnormal text\n"))
	if len(f) != 0 {
		t.Errorf("expected no finding for a single leading BOM, got %+v", f)
	}
}

func TestCFG024_MidFileBOM_Flagged(t *testing.T) {
	f := CFG024.Check(claudeMDTarget("normal" + string(rune(0xFEFF)) + "hidden"))
	if len(f) != 1 {
		t.Errorf("expected finding for mid-file U+FEFF, got %+v", f)
	}
}

func TestCFG024_CleanText_NoFinding(t *testing.T) {
	f := CFG024.Check(claudeMDTarget("# Project memory\n\nRun `make test` before committing. Use UTF-8 like café, naïve, 日本語.\n"))
	if len(f) != 0 {
		t.Errorf("expected no finding for clean text, got %+v", f)
	}
}

func TestCFG024_MessageNamesCodepoint(t *testing.T) {
	f := CFG024.Check(claudeMDTarget("x" + string(rune(0x202E)) + "y"))
	if len(f) != 1 || !strings.Contains(f[0].Message, "U+202E") {
		t.Errorf("expected message to name U+202E, got %+v", f)
	}
}

func TestCFG024_NoClaudeMD_NoFinding(t *testing.T) {
	if f := CFG024.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding when no CLAUDE.md, got %+v", f)
	}
}
