// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

// CFG036 (#1813): a public key with a placeholder name is not a sensitive read.
func TestCFG036_PlaceholderPublicKey1813(t *testing.T) {
	for _, content := range []string{
		`KEY=$(cat ~/.ssh/<your-key>.pub)`,
		`KEY=$(cat ~/.ssh/{key}.pub)`,
		`KEY=$(cat ~/.ssh/$KEY.pub)`,
		`KEY=$(cat ~/.ssh/${KEY}.pub)`,
	} {
		if f := CFG036.Check(instrContent("# Setup\n\n```sh\n" + content + "\n```\n")); len(f) != 0 {
			t.Errorf("placeholder public key must not be reported: %q -> %+v", content, f)
		}
	}
	// private keys and placeholders without .pub stay reported.
	for _, content := range []string{
		`KEY=$(cat ~/.ssh/<your-key>)`,
		`KEY=$(cat ~/.ssh/id_ed25519)`,
	} {
		f := CFG036.Check(instrContent("# Setup\n\n```sh\n" + content + "\n```\n"))
		if len(f) == 0 || !strings.Contains(f[0].Message, "Part A") {
			t.Errorf("must stay Part A: %q -> %+v", content, f)
		}
	}
}
