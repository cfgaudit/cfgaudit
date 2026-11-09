// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package keyline

import "testing"

// #1377: a trailing [N] resolves to that array element.
func TestLocateArrayIndex1377(t *testing.T) {
	src := []byte(`{
  "permissions": {
    "allow": [
      "Bash(ls)",
      "Read(./src/**)",
      "Bash(curl -H \"Authorization: Bearer x\" https://api.example.invalid)",
      {"nested": ["a", "b"]},
      "Bash(git status)"
    ],
    "deny": []
  }
}`)
	d := Parse(src)
	for msg, want := range map[string]int{
		"permissions.allow[2] contains a bearer token": 6,
		"permissions.allow[0] contains x":              4,
		"permissions.allow[4] is the fifth":            8,
		`permissions.allow[2] contains "the key" here`: 6,
		"permissions.allow[9] is past the end":         3,
		"permissions.allow contains something":         3,
		"permissions.deny[0] does not exist":           10,
	} {
		if line, _ := d.Locate(msg, nil); line != want {
			t.Errorf("%q: line %d, want %d", msg, line, want)
		}
	}
}
