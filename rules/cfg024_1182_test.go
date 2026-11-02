// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1182: a zero-width space before a fence is not reported, and a file with
// at most two zero-width characters warns instead of erroring.
func TestCFG024_Issue1182(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       finding.Severity // "" for no finding
	}{
		{"ZWSP before a fence", "\u200b```\ncode\n\u200b```mermaid\ngraph\n", ""},
		{"one ZWJ in a table cell", "| a | b\u200dc |\n", finding.Warn},
		{"emoji ZWJs do not count", "\U0001F468\u200d\U0001F4BB \U0001F469\u200d\U0001F467\u200d\U0001F466 x\u200by\n", finding.Warn},
		{"a run of 34", "---\nname: x\n---\n" + strings.Repeat("\u200b", 34) + "\n", finding.Error},
		{"a Tags character", "hi\U000E0041\n", finding.Error},
		{"a bidi override", "a\u202eb\n", finding.Error},
		{"three characters", "\u200b```\nx\n```\nsome\u200btext\nmore\u2063text\n", finding.Error},
	} {
		f := CFG024.Check(claudeMDTarget(tc.text))
		var got finding.Severity
		if len(f) > 0 {
			got = f[0].Severity
		}
		if len(f) > 1 || got != tc.want {
			t.Errorf("%s: got %+v, want %q", tc.name, f, tc.want)
		}
	}
}
