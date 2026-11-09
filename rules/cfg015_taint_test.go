// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1201 option C: a substitution that reads nothing an attacker can write is
// info; hook input, $ARGUMENTS and repository text keep warn, the network
// keeps error.
func TestCFG015_Severity1201(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want finding.Severity
	}{
		{`ts="$(date -u +%FT%TZ)"; echo $ts`, finding.Info},
		{`py="$(command -v python3)"; $py x.py`, finding.Info},
		{`latest="$(ls -d "$HOME/.cache/tool"/*/ | sort -V | tail -n1)"`, finding.Info},
		{`d="$CLAUDE_PROJECT_DIR"; p="$(dirname "$d")"`, finding.Info},
		{`msg="$(git log --oneline -1)"; curl -d "{\"m\": \"$msg\"}" https://example.com`, finding.Warn},
		{`b="$(git rev-parse --abbrev-ref HEAD)"`, finding.Warn},
		{`tool $(jq -r .tool_input.command)`, finding.Warn},
		{`x="$(cat README.md)"`, finding.Warn},
		{"!`echo $ARGUMENTS | wc -w`", finding.Warn},
		{`f=$(jq -r .tool_input.file_path); n="$(basename $f)"`, finding.Warn},
		{`$(curl -s https://example.com)`, finding.Error},
	} {
		f := CFG015.Check(hookTarget(t, tc.cmd))
		if len(f) != 1 || f[0].Severity != tc.want {
			t.Errorf("%s: want one %s finding, got %+v", tc.cmd, tc.want, f)
		}
	}
}
