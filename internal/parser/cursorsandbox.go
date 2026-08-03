package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// CursorSandbox is a partial representation of a Cursor `.cursor/sandbox.json`
// (Cursor 2.5+). Only the fields cfgaudit inspects are decoded; unknown keys are
// ignored.
//
// Cursor reads `~/.cursor/sandbox.json` and `<workspace>/.cursor/sandbox.json`
// and merges them "with per-repo settings taking priority", so a committed file
// wins over the settings a teammate chose for themselves. That is what makes the
// per-repo file a weakening surface rather than a preference.
type CursorSandbox struct {
	// Type selects the sandbox profile: "workspace_readwrite" (the default),
	// "workspace_readonly" (stricter), or "insecure_none", documented as
	// "disables the sandbox entirely".
	Type string `json:"type,omitempty"`

	// NetworkPolicy controls outbound traffic. Absent means Cursor's default,
	// which the reference states is deny.
	NetworkPolicy *CursorNetworkPolicy `json:"networkPolicy,omitempty"`

	// AdditionalReadwritePaths are "extra paths the agent can read and write"
	// beyond the workspace. AdditionalReadonlyPaths grant read access only, which
	// is not an escape route for writes but can still expose secrets to the agent.
	AdditionalReadwritePaths []string `json:"additionalReadwritePaths,omitempty"`
	AdditionalReadonlyPaths  []string `json:"additionalReadonlyPaths,omitempty"`

	// DisableTmpWrite removes default write access to /tmp and the system temp
	// directories. Setting it true makes the sandbox MORE restrictive, so it is
	// decoded for completeness and deliberately not flagged.
	DisableTmpWrite bool `json:"disableTmpWrite,omitempty"`

	// EnableSharedBuildCache "redirects build-tool caches (npm, cargo, pip, etc.)
	// to a shared tmpdir so sandboxed and unsandboxed commands share the same
	// caches" — a channel that crosses the sandbox boundary by design.
	EnableSharedBuildCache bool `json:"enableSharedBuildCache,omitempty"`
}

// CursorNetworkPolicy is the nested outbound-traffic policy. Default is the
// fallback for a host matching neither list; Cursor documents its default as
// "deny", and that deny always beats allow when a host matches both lists.
// Patterns may be exact domains, wildcards ("*.example.com") or CIDR ranges.
type CursorNetworkPolicy struct {
	Default string   `json:"default,omitempty"`
	Allow   []string `json:"allow,omitempty"`
	Deny    []string `json:"deny,omitempty"`
}

// Empty reports whether the file declared nothing cfgaudit inspects.
func (s *CursorSandbox) Empty() bool {
	if s == nil {
		return true
	}
	if s.Type != "" || s.EnableSharedBuildCache || s.DisableTmpWrite {
		return false
	}
	if len(s.AdditionalReadwritePaths) > 0 || len(s.AdditionalReadonlyPaths) > 0 {
		return false
	}
	np := s.NetworkPolicy
	return np == nil || (np.Default == "" && len(np.Allow) == 0 && len(np.Deny) == 0)
}

// ParseCursorSandbox reads and decodes a .cursor/sandbox.json. Cursor documents
// its config files with JSONC examples, so comments and trailing commas are
// stripped before decoding, as for .cursor/permissions.json.
func ParseCursorSandbox(path string) (*CursorSandbox, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var s CursorSandbox
	if err := json.Unmarshal(stripJSONC(data), &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &s, nil
}
