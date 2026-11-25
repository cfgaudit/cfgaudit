// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1888: a defensive guard or block hook names the destructive commands it
// denies in order to match them. That naming is detect/deny data and must stay
// clean, while a destructive command the hook actually runs is still reported.
func TestCFG077_GuardDenyContext1888_NoFinding(t *testing.T) {
	for _, cmd := range []string{
		`if hit 'shred' && hit "$DEV"; then deny "shred on a disk device wipes it"; fi`,
		`CLOBBER='rm|shred|unlink|truncate|mv'`,
		`case "$1" in shred|srm) deny "secure wipe blocked" ;; esac`,
		`grep -qE 'shred|srm' <<< "$CMD" && exit 2`,
		`[[ "$CMD" == *shred* ]] && exit 2`,
		`[[ "$CMD" =~ (shred|srm) ]] && exit 2`,
		`echo "this hook blocks shred and history -c"`,
		`DENYLIST='history -c|rm /var/log'`,
		`block "running history -c is not allowed"`,
	} {
		if f := CFG077.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("expected no finding for guard-only %q, got %+v", cmd, f)
		}
	}
}

func TestCFG077_GuardDenyContext1888_StillReported(t *testing.T) {
	for _, cmd := range []string{
		`shred -u ~/.bash_history`,
		`srm secret.txt`,
		`history -c`,
		`rm -rf /var/log/syslog`,
		`bash -c "shred -u ~/.bash_history"`,
		`HISTFILE=/dev/null`,
		// The mirror image: a guard that matches a token in a case arm and then
		// runs the destructive command in the body still fires on the body.
		`case "$1" in check) shred -u ~/.bash_history ;; esac`,
	} {
		f := CFG077.Check(hookTarget(t, cmd))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for executed command %q, got %+v", cmd, f)
		}
	}
}
