// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

// #1199: a variable the command assigns from something other than its input
// is not reported, and a single-quoted sh -c body is checked on its own.
func TestCFG009_Taint1199(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want string // "" for no finding
	}{
		{`fail=0; npm test || fail=1; [ $fail -ne 0 ] && exit 2`, ""},
		{`root=$(git rev-parse --show-toplevel || pwd); cd $root`, ""},
		{`bash -c 'FILE=$(jq -r .tool_input.file_path); cargo fmt -- "$FILE"'`, ""},
		{`r="${CLAUDE_PROJECT_DIR:-.}"; d="$r"; p="$(dirname "$d")"; cd $p`, ""},
		{`for f in a b c; do echo $f; done`, ""},
		{`f=$(jq -r .tool_input.file_path); eval "cat $f"`, "$f"},
		{`cmd=$(cat | jq -r .tool_input.command); bash -c "$cmd"`, "$cmd"},
		{"!`cat $ARGUMENTS`", "$ARGUMENTS"},
		{`FILE=$(jq -r .tool_input.file_path); bash -c "cargo fmt -- $FILE"`, "$FILE"},
		{`f=$(jq -r .tool_input.file_path); g=$f; echo $g`, "$g"},
		{`jq -r .tool_input.command | while read -r c; do echo $c; done`, "$c"},
		{`f=$(jq -r .tool_input.file_path); bash -c 'echo $f'`, "$f"},
		{`for f in $(jq -r '.files[]'); do rm $f; done`, "$f"},
		{`x=$1; rm $x`, "$x"},
		{`local f="$(cat)"; rm $f`, "$f"},
		{`read -p name -a arr; rm $arr`, "$arr"},
		{"v=`date +%s`; echo $v", ""},
		{`v='a b'\ c; w=$(printf '%s' "$(pwd)"); echo $v $w`, ""},
	} {
		f := CFG009.Check(hookTarget(t, tc.cmd))
		switch {
		case tc.want == "" && len(f) != 0:
			t.Errorf("%s: want no finding, got %s", tc.cmd, f[0].Message)
		case tc.want != "" && (len(f) != 1 || !strings.Contains(f[0].Message, tc.want)):
			t.Errorf("%s: want %s reported, got %+v", tc.cmd, tc.want, f)
		}
	}
}
