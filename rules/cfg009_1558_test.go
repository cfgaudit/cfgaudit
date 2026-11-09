// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"slices"
	"testing"
)

// #1558: a value echo or printf only prints is text, not a command.
func TestCFG009Printed1558(t *testing.T) {
	for cmd, want := range map[string][]string{
		`echo $TITLE`:                              nil,
		`echo -e "Title: $TITLE" $BODY`:            nil,
		`printf '%s\n' $X`:                         nil,
		`printf "%s %s" "$A" $B; echo done`:        nil,
		`f=$(jq -r .p); echo $f`:                   nil,
		`echo $X >> log.txt`:                       nil,
		`eval "echo $X"`:                           {"$X"},
		`sh -c "echo $X"`:                          {"$X"},
		`$X --version`:                             {"$X"},
		`echo $X | sh`:                             {"$X"},
		`echo $X | xargs rm`:                       {"$X"},
		`bash <(echo $X)`:                          {"$X"},
		`rm $(echo $X)`:                            {"$X"},
		"rm `echo $X`":                             {"$X"},
		`run "$(echo $X)"`:                         {"$X"},
		`printf $X`:                                {"$X"},
		`printf -v $N '%s' x`:                      {"$N"},
		`echo x > $F`:                              {"$F"},
		`echo x >$F`:                               {"$F"},
		`echo x 2> $F`:                             {"$F"},
		`echo $A; cat $B`:                          {"$B"},
		`echo "$X`:                                 {"$X"},
		`echo $CLAUDE_FILE_PATH`:                   {"$CLAUDE_FILE_PATH"},
		`echo "export Y=$X" >> "$CLAUDE_ENV_FILE"`: {"$X"},
		`echo "v $X" >> $GITHUB_ENV`:               {"$X", "$GITHUB_ENV"},
		`echo "v=$X" >> ${GITHUB_OUTPUT}`:          {"$GITHUB_OUTPUT"},
	} {
		if got := extractShellVars(cmd, true); !slices.Equal(got, want) {
			t.Errorf("%q: got %v, want %v", cmd, got, want)
		}
	}
}
