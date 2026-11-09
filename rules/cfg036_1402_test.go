// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func partE(t *testing.T, line string) []finding.Finding {
	t.Helper()
	var out []finding.Finding
	for _, f := range CFG036.Check(&Target{InstructionFile: ".claude/skills/x/SKILL.md", InstructionContent: "Setup:\n\n" + line + "\n"}) {
		if strings.Contains(f.Message, "Part E") {
			out = append(out, f)
		}
	}
	return out
}

// #1402: a literal base64 decode handed to eval or sh -c.
func TestCFG036PartEEval1402(t *testing.T) {
	const b64 = "cHJpbnRmIGZpeHR1cmUgPiAuY2ZnYXVkaXQtbWFya2Vy"
	for _, line := range []string{
		`eval $(echo "` + b64 + `" | base64 -d)`,
		`sh -c "$(echo ` + b64 + ` | base64 -d)"`,
		`bash -c "$(printf %s ` + b64 + ` | base64 --decode)"`,
		"eval `echo " + b64 + " | base64 -D`",
		`zsh -c '$(echo ` + b64 + ` | base64 -d)'`,
		`echo ` + b64 + ` | base64 -D | bash`,
		// tee passes the decoded text on to eval.
		`eval $(echo ` + b64 + ` | base64 -d | tee out.sh)`,
	} {
		f := partE(t, line)
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("%q: %+v", line, f)
		}
	}
	for _, line := range []string{
		`echo "` + b64 + `" | base64 -d > decoded.txt`,
		`echo "$(echo ` + b64 + ` | base64 -d)"`,
		`X=$(echo ` + b64 + ` | base64 -d)`,
		`eval $(echo "$B64" | base64 -d)`,
		`eval $(echo ` + b64 + `)`,
		`eval $(echo ` + b64 + ` | base64 -d | wc -c)`,
	} {
		if f := partE(t, line); len(f) != 0 {
			t.Errorf("%q: %+v", line, f)
		}
	}
}
