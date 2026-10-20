package parser

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func parseCodexTOML(t *testing.T, body string) *CodexConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := ParseCodexConfig(path)
	if err != nil {
		t.Fatalf("ParseCodexConfig: %v", err)
	}
	return c
}

// The filesystem block mixes scalar knobs, scope keys, paths and nested scope
// tables. Only granting decisions count, and nested tables are walked only
// under ":root".
func TestCodexPermissionProfile_FilesystemGrants(t *testing.T) {
	c := parseCodexTOML(t, `
default_permissions = "p"

[permissions.p.filesystem]
glob_scan_max_depth = 3
":root" = " Read "
":tmpdir" = "write"
"~/.ssh" = "read"
"/etc" = "WRITE"
"/denied" = "deny"
"/nothing" = "none"
"/odd" = "maybe"

[permissions.p.filesystem.":workspace_roots"]
"**/*.env" = "write"
`)
	p := c.Permissions["p"]
	roots, all, writes := p.FilesystemGrants()
	if want := []string{`:root = "Read"`}; !reflect.DeepEqual(roots, want) {
		t.Errorf("rootScopes = %v, want %v", roots, want)
	}
	// ":tmpdir" is a bounded scope key, not a path; deny, none and an unknown
	// decision withhold; the nested ":workspace_roots" glob stays in the project.
	if want := []string{"/etc", "~/.ssh"}; !reflect.DeepEqual(all, want) {
		t.Errorf("allPaths = %v, want %v", all, want)
	}
	if want := []string{"/etc"}; !reflect.DeepEqual(writes, want) {
		t.Errorf("writePaths = %v, want %v", writes, want)
	}
}

// A nested table under ":root" widens the whole filesystem, so its granting
// globs are recorded; non-string values and withholding decisions are not.
func TestCodexPermissionProfile_FilesystemGrantsRootTable(t *testing.T) {
	p := CodexPermissionProfile{Filesystem: map[string]any{
		":root": map[string]any{
			" /var/** ": "write",
			"/opt/**":   "read",
			"/srv/**":   "deny",
			"/num":      int64(1),
		},
	}}
	roots, all, writes := p.FilesystemGrants()
	if len(roots) != 0 {
		t.Errorf("a ':root' table is not a scalar root grant, got %v", roots)
	}
	if want := []string{"/opt/**", "/var/**"}; !reflect.DeepEqual(all, want) {
		t.Errorf("allPaths = %v, want %v", all, want)
	}
	if want := []string{"/var/**"}; !reflect.DeepEqual(writes, want) {
		t.Errorf("writePaths = %v, want %v", writes, want)
	}
}

func TestCodexPermissionNetwork_EgressAllowlist(t *testing.T) {
	var nilNet *CodexPermissionNetwork
	if hosts, catchAll := nilNet.EgressAllowlist(); hosts != nil || catchAll {
		t.Errorf("nil network: got %v %v", hosts, catchAll)
	}
	for _, tc := range []struct {
		name     string
		domains  map[string]string
		hosts    []string
		catchAll bool
	}{
		{"scoped", map[string]string{"github.com": "allow", " *.npmjs.org ": "ALLOW"},
			[]string{"*.npmjs.org", "github.com"}, false},
		// A deny entry narrows; it is not part of the allowlist.
		{"deny ignored", map[string]string{"evil.example": "deny", "github.com": "allow"},
			[]string{"github.com"}, false},
		{"bare wildcard", map[string]string{"*": "allow"}, []string{"*"}, true},
		{"double wildcard", map[string]string{"**": " allow "}, []string{"**"}, true},
		// A suffix wildcard names a real domain and is ordinary scoping.
		{"suffix wildcard", map[string]string{"*.github.com": "allow"}, []string{"*.github.com"}, false},
		{"denied catch-all", map[string]string{"*": "deny"}, nil, false},
	} {
		n := &CodexPermissionNetwork{Domains: tc.domains}
		hosts, catchAll := n.EgressAllowlist()
		if !reflect.DeepEqual(hosts, tc.hosts) || catchAll != tc.catchAll {
			t.Errorf("%s: got %v %v, want %v %v", tc.name, hosts, catchAll, tc.hosts, tc.catchAll)
		}
	}
}

func TestCodexConfig_SelectedPermissionProfiles(t *testing.T) {
	profiles := map[string]CodexPermissionProfile{
		"child":  {Extends: " parent "},
		"parent": {Extends: "grand"},
		"grand":  {},
		"loopA":  {Extends: "loopB"},
		"loopB":  {Extends: "loopA"},
		"dangle": {Extends: "missing"},
		"onBuiltin": {
			Extends: ":workspace",
		},
	}
	names := func(ps []NamedCodexProfile) []string {
		var out []string
		for _, p := range ps {
			out = append(out, p.Name)
		}
		return out
	}
	for _, tc := range []struct {
		name, selected string
		want           []string
	}{
		{"unset", "", nil},
		{"built-in", ":read-only", nil},
		{"undefined", "nobody", nil},
		// Resolution order follows extends to the end of the chain.
		{"chain", " child ", []string{"child", "parent", "grand"}},
		// A cycle stops at the first repeat instead of looping.
		{"cycle", "loopA", []string{"loopA", "loopB"}},
		// An undefined parent ends the chain after the profiles that resolved.
		{"dangling parent", "dangle", []string{"dangle"}},
		// A built-in parent is not defined in the file.
		{"built-in parent", "onBuiltin", []string{"onBuiltin"}},
	} {
		c := &CodexConfig{DefaultPermissions: tc.selected, Permissions: profiles}
		if got := names(c.SelectedPermissionProfiles()); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	var nilCfg *CodexConfig
	if got := nilCfg.SelectedPermissionProfiles(); got != nil {
		t.Errorf("nil config: got %v", got)
	}
	if got := (&CodexConfig{DefaultPermissions: "p"}).SelectedPermissionProfiles(); got != nil {
		t.Errorf("no [permissions] table: got %v", got)
	}
}

// An explicit enabled = false is a denial, not the zero value of a missing key.
func TestCodexPermissionProfile_NetworkOpened(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		name string
		p    CodexPermissionProfile
		want bool
	}{
		{"no block", CodexPermissionProfile{}, false},
		{"no enabled key", CodexPermissionProfile{Network: &CodexPermissionNetwork{Mode: "full"}}, false},
		{"enabled false", CodexPermissionProfile{Network: &CodexPermissionNetwork{Enabled: &off}}, false},
		{"enabled true", CodexPermissionProfile{Network: &CodexPermissionNetwork{Enabled: &on}}, true},
	} {
		if got := tc.p.NetworkOpened(); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
