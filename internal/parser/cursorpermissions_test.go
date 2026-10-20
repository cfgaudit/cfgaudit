package parser

import "testing"

// Empty is true only when the file declares nothing cfgaudit inspects, so no
// target is built for it.
func TestCursorPermissions_Empty(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *CursorPermissions
		want bool
	}{
		{"nil", nil, true},
		{"zero", &CursorPermissions{}, true},
		{"mcp allowlist", &CursorPermissions{MCPAllowlist: []string{"srv:*"}}, false},
		{"terminal allowlist", &CursorPermissions{TerminalAllowlist: []string{"git"}}, false},
		{"empty autoRun", &CursorPermissions{AutoRun: &CursorAutoRun{}}, true},
		{"autoRun allow", &CursorPermissions{AutoRun: &CursorAutoRun{AllowInstructions: []string{"x"}}}, false},
		{"autoRun block", &CursorPermissions{AutoRun: &CursorAutoRun{BlockInstructions: []string{"x"}}}, false},
	} {
		if got := tc.p.Empty(); got != tc.want {
			t.Errorf("%s: Empty = %v, want %v", tc.name, got, tc.want)
		}
	}
}
