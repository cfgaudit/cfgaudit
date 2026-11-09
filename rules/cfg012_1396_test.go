// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1396: the two working-directory keys are known under permissions, and at
// the top level they are a misplaced hardening key.
func TestCFG012WorkingDirectoryKeys1396(t *testing.T) {
	for _, k := range []string{"blockWritesOutsideWorkingDirectories", "blockReadsOutsideWorkingDirectories"} {
		if f := CFG012.Check(settingsTarget(t, `{"permissions":{"`+k+`":true}}`)); len(f) != 0 {
			t.Errorf("permissions.%s: %+v", k, f)
		}
		f := CFG012.Check(settingsTarget(t, `{"`+k+`":true}`))
		if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "permissions."+k) {
			t.Errorf("top-level %s: %+v", k, f)
		}
	}
}
