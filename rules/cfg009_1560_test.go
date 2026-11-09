// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"slices"
	"testing"
)

// #1560: a stdin-reading program after a pipe reads the pipe, and a custom
// command's !{...} gets no hook input on stdin.
func TestCFG009Pipeline1560(t *testing.T) {
	for _, tc := range []struct {
		cmd       string
		hookStdin bool
		want      []string
	}{
		{`TAGS=$(git tag --sort=-v:refname | head -n 2); LATEST=$(echo "$TAGS" | sed -n '1p'); PREVIOUS=$(echo "$TAGS" | sed -n '2p'); git log $PREVIOUS..$LATEST`, true, nil},
		{`FILE=$(jq -r .tool_input.file_path); eval "cat $FILE"`, true, []string{"$FILE"}},
		{`X=$(cat | tr a b); echo $X`, true, []string{"$X"}},
		{`jq -r .x | while read -r c; do echo $c; done`, true, []string{"$c"}},
		{`X=$(git log | python3 -c 'import sys; print(sys.stdin.read())'); echo $X`, true, []string{"$X"}},
		{`A=$(false || cat); echo $A`, true, []string{"$A"}},
		{`f=$(tr -d '\n' | grep -o '"file_path"' | head -1); fmt $f`, true, []string{"$f"}},
		{`f=$(git diff --name-only | grep '\.go$' | head -1); fmt $f`, true, nil},
		{`X=$(cat); echo $X`, false, nil},
		{`X=$(echo $ARGUMENTS); echo $X`, false, []string{"$ARGUMENTS", "$X"}},
	} {
		if got := extractShellVars(tc.cmd, tc.hookStdin); !slices.Equal(got, tc.want) {
			t.Errorf("%q (hook stdin %v): got %v, want %v", tc.cmd, tc.hookStdin, got, tc.want)
		}
	}
}
