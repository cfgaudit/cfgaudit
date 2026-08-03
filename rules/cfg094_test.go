package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func TestCFG094_AllowInstructions(t *testing.T) {
	f := CFG094.Check(cursorPermissionsTarget(&parser.CursorPermissions{
		AutoRun: &parser.CursorAutoRun{
			AllowInstructions: []string{"Read-only inspections of build artifacts under ./dist are fine."},
		},
	}))
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 Warn, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "./dist") {
		t.Errorf("message should quote the instruction, got %q", f[0].Message)
	}
	if !strings.Contains(f[0].Message, "Auto-review") {
		t.Errorf("message must name the mode the instructions are consulted in, got %q", f[0].Message)
	}
}

// block_instructions pushes the classifier toward asking, the safe direction.
func TestCFG094_BlockInstructionsAloneNotFlagged(t *testing.T) {
	f := CFG094.Check(cursorPermissionsTarget(&parser.CursorPermissions{
		AutoRun: &parser.CursorAutoRun{
			BlockInstructions: []string{"Reject delete operations so I can review them."},
		},
	}))
	if len(f) != 0 {
		t.Fatalf("expected no findings for block_instructions alone, got %+v", f)
	}
}

// When both exist the finding says the block half is not the concern, so a
// reader is not left thinking their caution was flagged.
func TestCFG094_BothKindsPresent(t *testing.T) {
	f := CFG094.Check(cursorPermissionsTarget(&parser.CursorPermissions{
		AutoRun: &parser.CursorAutoRun{
			AllowInstructions: []string{"Anything under ./dist is fine."},
			BlockInstructions: []string{"Reject deletes."},
		},
	}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "block_instructions are not the concern") {
		t.Errorf("message should exonerate block_instructions, got %q", f[0].Message)
	}
}

// A long instruction is truncated and the remainder counted, so one prose block
// cannot swamp the finding line.
func TestCFG094_LongInstructionTruncated(t *testing.T) {
	long := strings.Repeat("allow everything please ", 20)
	f := CFG094.Check(cursorPermissionsTarget(&parser.CursorPermissions{
		AutoRun: &parser.CursorAutoRun{AllowInstructions: []string{long, "second", "third"}},
	}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "…") {
		t.Errorf("long instruction should be truncated, got %q", f[0].Message)
	}
	if !strings.Contains(f[0].Message, "and 2 more") {
		t.Errorf("remaining instructions should be counted, got %q", f[0].Message)
	}
	if strings.Contains(f[0].Message, long) {
		t.Errorf("the full instruction must not be inlined")
	}
}

func TestCFG094_SingleExtraInstructionIsSingular(t *testing.T) {
	f := CFG094.Check(cursorPermissionsTarget(&parser.CursorPermissions{
		AutoRun: &parser.CursorAutoRun{AllowInstructions: []string{"first", "second"}},
	}))
	if len(f) != 1 || !strings.Contains(f[0].Message, "and 1 more") {
		t.Fatalf("expected \"and 1 more\", got %+v", f)
	}
}

func TestCFG094_NoFindings(t *testing.T) {
	cases := map[string]*Target{
		"no permissions file": {Scope: finding.ScopeProject},
		"no autoRun":          cursorPermissionsTarget(&parser.CursorPermissions{TerminalAllowlist: []string{"git"}}),
		"empty autoRun":       cursorPermissionsTarget(&parser.CursorPermissions{AutoRun: &parser.CursorAutoRun{}}),
		"blank instructions": cursorPermissionsTarget(&parser.CursorPermissions{
			AutoRun: &parser.CursorAutoRun{AllowInstructions: []string{"", "  "}},
		}),
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			if f := CFG094.Check(target); len(f) != 0 {
				t.Errorf("expected no findings, got %+v", f)
			}
		})
	}
	t.Run("nil target", func(t *testing.T) {
		if f := CFG094.Check(nil); len(f) != 0 {
			t.Errorf("expected no findings, got %+v", f)
		}
	})
}

func TestCFG094_UserScopeSkipped(t *testing.T) {
	target := cursorPermissionsTarget(&parser.CursorPermissions{
		AutoRun: &parser.CursorAutoRun{AllowInstructions: []string{"anything goes"}},
	})
	target.Scope = finding.ScopeUser
	if f := CFG094.Check(target); len(f) != 0 {
		t.Errorf("expected no findings at user scope, got %+v", f)
	}
}
