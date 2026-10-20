package parser

import "testing"

// Empty is true only when the file declares nothing cfgaudit inspects, so no
// target is built for it.
func TestCursorSandbox_Empty(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    *CursorSandbox
		want bool
	}{
		{"nil", nil, true},
		{"zero", &CursorSandbox{}, true},
		{"type", &CursorSandbox{Type: "workspace_readwrite"}, false},
		{"shared build cache", &CursorSandbox{EnableSharedBuildCache: true}, false},
		{"disable tmp write", &CursorSandbox{DisableTmpWrite: true}, false},
		{"readwrite paths", &CursorSandbox{AdditionalReadwritePaths: []string{"/x"}}, false},
		{"readonly paths", &CursorSandbox{AdditionalReadonlyPaths: []string{"/x"}}, false},
		{"read boundary", &CursorSandbox{ReadBoundary: "workspace"}, false},
		{"read paths", &CursorSandbox{AdditionalReadPaths: []string{"/x"}}, false},
		{"empty network policy", &CursorSandbox{NetworkPolicy: &CursorNetworkPolicy{}}, true},
		{"network default", &CursorSandbox{NetworkPolicy: &CursorNetworkPolicy{Default: "allow"}}, false},
		{"network allow", &CursorSandbox{NetworkPolicy: &CursorNetworkPolicy{Allow: []string{"*"}}}, false},
		{"network deny", &CursorSandbox{NetworkPolicy: &CursorNetworkPolicy{Deny: []string{"x"}}}, false},
	} {
		if got := tc.s.Empty(); got != tc.want {
			t.Errorf("%s: Empty = %v, want %v", tc.name, got, tc.want)
		}
	}
}
