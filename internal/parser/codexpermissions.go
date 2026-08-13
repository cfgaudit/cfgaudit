package parser

import (
	"sort"
	"strings"
)

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

	Network *CodexPermissionNetwork `toml:"network"`

	// WorkspaceRoots is the profile-level array the Codex schema documents. It is
	// kept because the schema carries it, but it is not what people write: across
	// 69 real .codex/config.toml files it appears zero times, while the nested
	// [<profile>.filesystem.":workspace_roots"] table appears 37 times. Do not
	// mistake a count of the string "workspace_roots" for a count of this field.
	WorkspaceRoots []string `toml:"workspace_roots"`

	// Filesystem is the profile's filesystem block, the most used part of the
	// whole mechanism: 39 of those same 69 files carry one.
	//
	// It is decoded loosely because it mixes three value kinds under one table:
	//
	//	[permissions.p.filesystem]
	//	glob_scan_max_depth = 3          # a scalar knob
	//	":root" = "deny"                 # a scope key  -> decision
	//	"~/.ssh" = "deny"                # a path       -> decision
	//
	//	[permissions.p.filesystem.":workspace_roots"]
	//	"**/*.env" = "deny"              # a nested scope table of glob -> decision
	//
	// Decisions observed across the corpus: deny (176), allow (134), write (72),
	// read (53), none (51).
	Filesystem map[string]any `toml:"filesystem"`
}

// grantingFilesystemDecisions are the filesystem decisions that hand out access,
// mapped to whether the grant is a write. Measured across the corpus, a
// filesystem block uses exactly four values: deny (177), write (72), read (53)
// and none (51). "deny" and "none" withhold, and an unrecognised value is treated
// as not granting: reporting a decision whose meaning is unknown would be a guess.
//
// Read and write are kept apart because they matter in opposite places. A read
// grant to a credential path is already an exfiltration channel, which is why
// CFG095 reports a read of one. A read grant to a system path is how the agent
// reaches its own toolchain: every system-path grant in the corpus is a read of
// /bin, /usr/bin or the command line tools.
var grantingFilesystemDecisions = map[string]bool{"read": false, "write": true}

// rootScopeKey is the one built-in scope covering the whole filesystem. The other
// keys seen in the wild bound themselves: ":minimal", ":project_roots",
// ":workspace_roots", ":tmpdir" and ":slash_tmp" all name a subset, so granting
// over them is ordinary configuration rather than a finding.
const rootScopeKey = ":root"

// FilesystemGrants splits a profile's filesystem block into the entries that hand
// out access: rootScopes carries a granting decision on ":root", and allPaths /
// writePaths carry the granting path and glob keys, for the caller to classify by
// sensitivity the same way writable_roots is classified. writePaths is a subset
// of allPaths.
//
// Nested scope tables are walked only under ":root". The bounded scopes resolve
// against the workspace, so a granting glob inside one of them stays inside the
// project and is not a widening.
func (p CodexPermissionProfile) FilesystemGrants() (rootScopes, allPaths, writePaths []string) {
	record := func(key string, isWrite bool) {
		allPaths = append(allPaths, key)
		if isWrite {
			writePaths = append(writePaths, key)
		}
	}
	for key, val := range p.Filesystem {
		k := strings.TrimSpace(key)
		switch v := val.(type) {
		case string:
			isWrite, granting := grantingFilesystemDecisions[strings.ToLower(strings.TrimSpace(v))]
			if !granting {
				continue
			}
			if k == rootScopeKey {
				rootScopes = append(rootScopes, k+" = \""+strings.TrimSpace(v)+"\"")
			} else if !strings.HasPrefix(k, ":") {
				record(k, isWrite)
			}
		case map[string]any:
			if k != rootScopeKey {
				continue // a bounded scope: its globs resolve inside the workspace
			}
			for glob, decision := range v {
				s, ok := decision.(string)
				if !ok {
					continue
				}
				if isWrite, granting := grantingFilesystemDecisions[strings.ToLower(strings.TrimSpace(s))]; granting {
					record(strings.TrimSpace(glob), isWrite)
				}
			}
		}
	}
	sort.Strings(rootScopes)
	sort.Strings(allPaths)
	sort.Strings(writePaths)
	return rootScopes, allPaths, writePaths
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

	// Domains is the egress allowlist, written as a TOML table of host pattern to
	// decision rather than an array:
	//
	//	[permissions.p.network.domains]
	//	"github.com" = "allow"
	//	"*.githubusercontent.com" = "allow"
	//
	// It decides how far an opened network reaches, so it is what separates
	// scoped egress from open egress. Measured across 69 real .codex/config.toml
	// files: 20 carry the table, and of the 22 that open the network, 17 scope it
	// this way (#483).
	Domains map[string]string `toml:"domains"`
}

// catchAllDomainPatterns are the allowlist keys that match every host, so an
// allowlist containing one restricts nothing. Deliberately only the bare
// wildcards: "*.github.com" and "**.github.com" name a real suffix and are
// ordinary scoping.
var catchAllDomainPatterns = map[string]bool{"*": true, "**": true}

// EgressAllowlist returns the host patterns the network block allows, sorted, and
// whether any of them is a catch-all that makes the allowlist meaningless.
//
// Only "allow" decisions count. A "deny" entry narrows an allowlist that some
// other entry opened, so counting it as scoping would read a restriction as a
// grant.
func (n *CodexPermissionNetwork) EgressAllowlist() (hosts []string, catchAll bool) {
	if n == nil {
		return nil, false
	}
	for pattern, decision := range n.Domains {
		if !strings.EqualFold(strings.TrimSpace(decision), "allow") {
			continue
		}
		p := strings.TrimSpace(pattern)
		if catchAllDomainPatterns[p] {
			catchAll = true
		}
		hosts = append(hosts, p)
	}
	sort.Strings(hosts)
	return hosts, catchAll
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
