// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import "strings"

// deniedInSameFile reports whether a permissions.deny entry of t's settings
// file blocks everything the allow entry grants (#1041). Claude Code checks
// deny before allow, so such an allow entry has no effect: measured with
// 2.1.312, allow Bash(touch:*) with deny Bash(touch:*) blocked the command,
// and a bare deny Bash removed the tool. Covering means the identical entry,
// the bare tool name, or a broader pattern of the same tool (Bash(curl:*)
// covers Bash(curl https://x:*)). A partial overlap, allow Bash with deny
// Bash(rm:*), is not covering. Only the same file counts: cfgaudit cannot see
// the deny lists of the other settings layers.
func deniedInSameFile(t *Target, allow string) bool {
	allow = strings.TrimSpace(allow)
	tool, _, _ := strings.Cut(allow, "(")
	ap, ok := parsePerm(allow)
	if !ok && tool == allow {
		// A bare tool name grants every use of the tool.
		ap, ok = permPattern{tool: allow, wildcard: true}, true
	}
	for _, d := range t.effectiveDeny() {
		d = strings.TrimSpace(d)
		if d == allow || d == tool {
			return true
		}
		if dp, dok := parsePerm(d); dok && ok && covers(dp, ap) {
			return true
		}
	}
	return false
}
