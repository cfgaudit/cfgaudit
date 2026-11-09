// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"reflect"
	"strings"
	"testing"
)

// A copy of a hook variable Claude Code never sets is empty, and a quoted use
// inside "$( )" is quoted (#1376).
func TestExtractShellVars1376(t *testing.T) {
	for cmd, want := range map[string][]string{
		`f="$TOOL_INPUT_FILE_PATH"; case "$f" in *.ts) npx prettier --write "$(dirname "$f")" ;; esac`: {"$TOOL_INPUT_FILE_PATH"},
		`for f in $CLAUDE_FILE_PATHS; do echo "NOTE: $f changed"; done`:                                {"$CLAUDE_FILE_PATHS"},
		`f=$(jq -r .tool_input.file_path); rm $f`:                                                      {"$f"},
		// The command sets the name itself, from its input.
		`TOOL_INPUT_FILE_PATH=$(jq -r .path); f=$TOOL_INPUT_FILE_PATH; rm $f`: {"$TOOL_INPUT_FILE_PATH", "$f"},
		// Copied from a real variable, not one that does not exist.
		`f=$USER_PATH; rm $f`: {"$USER_PATH", "$f"},
		// Inside the substitution the quoting counts as it does outside.
		`f=$(jq -r .p); echo "$(dirname $f)"`:      {"$f"},
		`f=$(jq -r .p); echo "$(dirname "$f")"`:    nil,
		`f=$(jq -r .p); echo "a $(b "$(c "$f")")"`: nil,
		`f=$(jq -r .p); echo "$(b '$f' "$f")"`:     nil,
		`f=$(jq -r .p); echo "$(echo \" "$f")"`:    nil,
		`f=$(jq -r .p); echo "$(b (c) "$f")"`:      nil,
		// A reference next to a substitution stays reported.
		`f=$(jq -r .p); run "$(date) $f"`: {"$f"},
		// Text parsed again undoes the quoting.
		`f=$(jq -r .p); echo "$(eval "$f")"`: {"$f"},
		// Arithmetic and an unclosed substitution are not commands.
		`f=$(jq -r .p); run "$((1+2)) $f"`: {"$f"},
		`f=$(jq -r .p); echo "$(date $f`:   {"$f"},
	} {
		if got := extractShellVars(cmd, true); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", cmd, got, want)
		}
	}
}

// The info for the variable stays, and no warn is added for its copy.
func TestCFG009_CopyOfUnsetVariable1376(t *testing.T) {
	cmd := `for f in $CLAUDE_FILE_PATHS; do echo "NOTE: $f changed"; done`
	if got := extractShellVars(cmd, true); len(got) != 1 || !strings.Contains(got[0], "CLAUDE_FILE_PATHS") || !undefinedClaudeHookVars[got[0]] {
		t.Errorf("got %v", got)
	}
	if neverSet("f", shellTaint{}, nil) {
		t.Error("f is not one of the unset names")
	}
	if neverSet("CLAUDE_FILE_PATHS", shellTaint{}, shellTaint{"CLAUDE_FILE_PATHS": true}) {
		t.Error("the enclosing command assigns it")
	}
}
