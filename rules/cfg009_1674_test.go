// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"reflect"
	"testing"
)

// The corpus shapes of #1674 interpolate nothing a shell would split or parse
// again; eval and a shell given a variable as its script still do.
func TestExtractShellVars1674(t *testing.T) {
	for cmd, want := range map[string][]string{
		// ${X:+word} in a quoted loop list, then an unquoted assignment.
		`for c in "${TOOL_HOME:+$TOOL_HOME/src/cli.ts}" ./x.js; do [ -f "$c" ] && coherence=$c && break; done`: nil,
		// Every reference inside the bash -c body is quoted or an assignment.
		`bash -c 'if [ -n "${CLAUDE_CODE_SESSION_ID:-}" ]; then p="$HOME/.cache/ops-${CLAUDE_CODE_SESSION_ID}"; mkdir -p "$p"; fi'`: nil,
		// Qwen Code's project directory, like Gemini's.
		`"$QWEN_PROJECT_DIR/.qwen/hooks/x.sh"`: nil,
		// "source" in a quoted message, and jq's . program, are not re-parses.
		`echo '{"additionalContext":"read source files first"}'; jq -r '.x as $open | $open' "$f"`: nil,
		`for f in a b; do jq -e . "$f" >/dev/null && jq -r '$open' "$f"; done`:                     nil,
		// The other expansion forms, with path characters or references.
		`run "${A:-./default/path}" "${B-$HOME/x}" "${C:?}"`: nil,
		// Still reported.
		`eval "$TOOL_INPUT"`: {"$TOOL_INPUT"},
		`bash -c "$CMD"`:     {"$CMD"},
		// An assignment matters where its variable is used unsafely.
		`v=$X; rm $v`:   {"$X", "$v"},
		`v="$X"; rm $v`: {"$X", "$v"},
		// The dot builtin in command position, and source as a command, still re-parse.
		`f=$(jq -r .p); . "$f"`:                        {"$f"},
		`f=$(jq -r .p); if true; then source "$f"; fi`: {"$f"},
		// A substitution inside double quotes is a command of its own.
		`f=$(jq -r .p); echo "$(eval "$f")"`: {"$f"},
	} {
		if got := extractShellVars(cmd, true); !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %v\nwant %v", cmd, got, want)
		}
	}
}

func TestUnquotedText1674(t *testing.T) {
	for in, want := range map[string]string{
		`echo 'read source'`:  `echo 'QQQQQQQQQQQ'`,
		`jq "x" . "$f"`:       `jq "Q" . "QQ"`,
		`echo "$(eval "$f")"`: `echo "$(eval "QQ")"`,
		`a\ b`:                `aQb`,
	} {
		if got := unquotedText(in); got != want {
			t.Errorf("unquotedText(%q) = %q, want %q", in, got, want)
		}
	}
}
