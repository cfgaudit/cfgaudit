package parser

import "strings"

// Codex named permission profiles: the [permissions] table and the
// default_permissions key that selects one of its entries.
//
// This is a second, richer permission mechanism sitting next to approval_policy
// (CFG063) and sandbox_mode / [sandbox_workspace_write] (CFG064). Per the Codex
// schema, a default_permissions name starting with ":" refers to a built-in
// profile; any other name is resolved from the [permissions] table.
//
// Neither key is on Codex's PROJECT_LOCAL_CONFIG_DENYLIST, so both cross from a
// committed project config. Measured end to end against codex-cli 0.147.0 in a
// trusted project directory:
//
//   - baseline, empty project config      → "restricted fs + restricted network"
//   - [permissions.p.network] enabled=true
//     with default_permissions = "p"      → "restricted fs + enabled network"
//   - default_permissions naming a profile
//     nobody defines                      → the whole config fails to load
//
// The trust precondition is real and was measured the same way: a deliberately
// malformed project config.toml is silent until the directory carries
// trust_level = "trusted", at which point its parse error surfaces. That is the
// same precondition CFG063/CFG064 already rely on, not an extra gate specific to
// permission profiles.
type CodexPermissionProfile struct {
	// Extends names another profile this one inherits from. Inheritance was
	// measured to carry the parent's posture: a child whose only content is
	// extends = "<permissive parent>" produced "enabled network" too, so a
	// profile cannot be judged from its own table alone.
	Extends string `toml:"extends"`

	Network        *CodexPermissionNetwork `toml:"network"`
	WorkspaceRoots []string                `toml:"workspace_roots"`
}

// CodexPermissionNetwork is a profile's [.network] block.
//
// Enabled is a pointer so an explicit `false` is distinguishable from an absent
// key: `false` was measured to keep the sandbox restricted, so it is a denial and
// must not be read as the zero value of a missing field.
//
// Mode ("limited" / "full") refines what an enabled network may reach rather than
// deciding whether it is open at all; both values reported as "enabled network".
// Enabled is therefore the field that decides.
type CodexPermissionNetwork struct {
	Enabled *bool  `toml:"enabled"`
	Mode    string `toml:"mode"`

	// ProxyURL and SocksURL route the agent's traffic through a host the config
	// chose. Committed, that is CFG021's threat model reached through Codex's own
	// permission mechanism.
	ProxyURL string `toml:"proxy_url"`
	SocksURL string `toml:"socks_url"`

	// The two fields upstream itself names "dangerously".
	DangerouslyAllowNonLoopbackProxy bool `toml:"dangerously_allow_non_loopback_proxy"`
	DangerouslyAllowAllUnixSockets   bool `toml:"dangerously_allow_all_unix_sockets"`
}

// NamedCodexProfile is a permission profile together with the name it is defined
// under, so a finding can say which table it came from.
type NamedCodexProfile struct {
	Name    string
	Profile CodexPermissionProfile
}

// SelectedPermissionProfiles returns the profiles a config actually reaches:
// the one default_permissions names, followed by everything it inherits through
// extends, in resolution order.
//
// It returns nothing when default_permissions is unset, when it names a built-in
// (a ":"-prefixed name, which is not resolved from the file), or when the name is
// undefined. That last case is not a silent skip in practice: Codex refuses to
// load a config whose default_permissions names an undefined profile, so such a
// file is broken rather than dangerous.
//
// A dormant profile that nothing selects is deliberately not returned. It is the
// same restraint that keeps [sandbox_workspace_write] inert under an explicit
// read-only mode: a table Codex never consults is not a finding.
func (c *CodexConfig) SelectedPermissionProfiles() []NamedCodexProfile {
	if c == nil || len(c.Permissions) == 0 {
		return nil
	}
	name := strings.TrimSpace(c.DefaultPermissions)
	if name == "" || strings.HasPrefix(name, ":") {
		return nil
	}

	var out []NamedCodexProfile
	seen := map[string]bool{}
	for name != "" && !seen[name] {
		seen[name] = true
		profile, ok := c.Permissions[name]
		if !ok {
			break
		}
		out = append(out, NamedCodexProfile{Name: name, Profile: profile})
		name = strings.TrimSpace(profile.Extends)
		if strings.HasPrefix(name, ":") {
			break // a built-in parent is not defined in this file
		}
	}
	return out
}

// NetworkOpened reports whether the profile's network block explicitly opens the
// network. An absent block, or an explicit enabled = false, leaves the sandbox
// restricted.
func (p CodexPermissionProfile) NetworkOpened() bool {
	return p.Network != nil && p.Network.Enabled != nil && *p.Network.Enabled
}
