package parser

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

// CodexConfig is a partial representation of an OpenAI Codex CLI config.toml
// (CODEX_HOME/config.toml, default ~/.codex/config.toml). Only the
// security-relevant fields cfgaudit inspects are decoded.
type CodexConfig struct {
	Model          string              `toml:"model"`
	ApprovalPolicy string              `toml:"approval_policy"`
	SandboxMode    string              `toml:"sandbox_mode"`
	MCPServers     map[string]CodexMCP `toml:"mcp_servers"`

	// ApprovalsReviewer routes escalated approval requests. "user" (the default)
	// asks the person; "auto_review" hands the decision to a subagent. Codex still
	// accepts the legacy spelling "guardian_subagent" as an alias for the same
	// value (codex-rs/protocol/src/config_types.rs), so both must be recognised.
	ApprovalsReviewer string `toml:"approvals_reviewer"`

	// SandboxWorkspaceWrite is the [sandbox_workspace_write] table, which Codex
	// consults only when the effective sandbox mode is workspace-write.
	SandboxWorkspaceWrite *CodexSandboxWorkspaceWrite `toml:"sandbox_workspace_write"`

	// DefaultPermissions and Permissions are Codex's named permission profiles,
	// a second permission mechanism next to approval_policy and sandbox_mode.
	// Neither key is on PROJECT_LOCAL_CONFIG_DENYLIST, so both cross from a
	// committed project config; see codexpermissions.go for the measurements.
	DefaultPermissions string                            `toml:"default_permissions"`
	Permissions        map[string]CodexPermissionProfile `toml:"permissions"`
	// Notify is a program (argv) Codex spawns on events; a committed value runs
	// attacker-controlled code, so it is scanned by the command-content rules.
	Notify []string `toml:"notify"`

	// ChatGPTBaseURL and the per-provider base_url are model endpoints the API key
	// is sent to; a cleartext remote value leaks it (CFG071).
	ChatGPTBaseURL string                   `toml:"chatgpt_base_url"`
	ModelProviders map[string]CodexProvider `toml:"model_providers"`

	// Hooks is the inline [hooks] table, the TOML twin of .codex/hooks.json.
	// `hooks` is deliberately NOT on Codex's PROJECT_LOCAL_CONFIG_DENYLIST, so a
	// committed table is discovered (#431). Its `state` sub-table is not decoded:
	// only User and SessionFlags layers may write hook state, so a repo cannot
	// self-trust its own hooks.
	Hooks CodexHookEventsToml `toml:"hooks"`
}

// HookEvents returns the inline [hooks] table as the shared CodexHooks shape.
// Nil when the config declares no hooks.
func (c *CodexConfig) HookEvents() *CodexHooks {
	if c == nil {
		return nil
	}
	return c.Hooks.Hooks()
}

// CodexSandboxWorkspaceWrite is the [sandbox_workspace_write] table
// (codex-rs/config/src/types.rs SandboxWorkspaceWrite).
//
// Only two of the four fields loosen anything:
//
//   - NetworkAccess re-enables outbound network from inside the sandbox, which
//     otherwise runs with NetworkSandboxPolicy::Restricted.
//   - WritableRoots adds directories the sandbox may write to on top of the
//     workspace.
//
// ExcludeTmpdirEnvVar and ExcludeSlashTmp go the other way. Codex builds the
// writable set as "workdir, then /tmp unless exclude_slash_tmp, then $TMPDIR
// unless exclude_tmpdir_env_var" (utils/sandbox-summary), so setting either to
// true REMOVES a writable location. They are decoded so the shape is documented
// and deliberately never flagged; the issue that requested this parsing listed
// them as looseners, which is the same trap Cursor's disableTmpWrite set in
// CFG095.
type CodexSandboxWorkspaceWrite struct {
	WritableRoots       []string `toml:"writable_roots"`
	NetworkAccess       bool     `toml:"network_access"`
	ExcludeTmpdirEnvVar bool     `toml:"exclude_tmpdir_env_var"`
	ExcludeSlashTmp     bool     `toml:"exclude_slash_tmp"`
}

// UsesAutoReviewer reports whether approvals are routed to the reviewer subagent
// rather than the user, accepting both the current spelling and Codex's legacy
// alias.
func (c *CodexConfig) UsesAutoReviewer() bool {
	if c == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(c.ApprovalsReviewer)) {
	case "auto_review", "guardian_subagent":
		return true
	}
	return false
}

// WorkspaceWriteTableApplies reports whether Codex would consult the
// [sandbox_workspace_write] table given this file's sandbox_mode.
//
// The table is read only under workspace-write. An explicit "read-only" ignores
// it, and "danger-full-access" disables the sandbox outright — that is CFG064's
// own error, strictly worse than anything in the table, so reporting the table
// there would add noise about settings Codex never reaches. An unset sandbox_mode
// resolves to workspace-write for a directory that carries a trust decision
// (codex-rs/config/src/config_toml.rs), which is the ordinary project case, so an
// omitted mode counts as applying.
func (c *CodexConfig) WorkspaceWriteTableApplies() bool {
	if c == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(c.SandboxMode)) {
	case "", "workspace-write":
		return true
	}
	return false
}

// CodexProvider is a [model_providers.<name>] table.
type CodexProvider struct {
	Name    string `toml:"name"`
	BaseURL string `toml:"base_url"`
}

// CodexMCP is a Codex [mcp_servers.<name>] table. stdio servers use
// command/args/env; streamable-http servers use url/env_http_headers.
type CodexMCP struct {
	Command        string            `toml:"command"`
	Args           []string          `toml:"args"`
	Env            map[string]string `toml:"env"`
	URL            string            `toml:"url"`
	EnvHTTPHeaders map[string]string `toml:"env_http_headers"`
}

// MCPServerMap converts the Codex mcp_servers tables to the shared MCPServer
// shape so the existing MCP rules apply unchanged (command/args/env, url, and
// env_http_headers mapped onto Headers).
func (c *CodexConfig) MCPServerMap() map[string]MCPServer {
	if c == nil || len(c.MCPServers) == 0 {
		return nil
	}
	out := make(map[string]MCPServer, len(c.MCPServers))
	for name, s := range c.MCPServers {
		out[name] = MCPServer{
			Command: s.Command,
			Args:    s.Args,
			Env:     s.Env,
			URL:     s.URL,
			Headers: s.EnvHTTPHeaders,
		}
	}
	return out
}

// ParseCodexConfig reads and decodes a Codex CLI config.toml file.
func ParseCodexConfig(path string) (*CodexConfig, error) {
	var c CodexConfig
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// ApplyProjectLayerDenylist clears the fields Codex refuses to honour from a
// project-local config layer, so cfgaudit does not report configuration the CLI
// ignores.
//
// Codex loads a committed .codex/config.toml as a project layer, but guards a
// subset of keys against it. From codex-rs/config/src/loader/mod.rs:
//
//	// Project-local config comes from repository contents, so it should not get to
//	// choose where a user's credentials are sent or which local commands are run.
//	const PROJECT_LOCAL_CONFIG_DENYLIST: &[&str] = &[
//	    "openai_base_url", "chatgpt_base_url", "apps_mcp_product_sku",
//	    "responses_api_metadata", "model_provider", "model_providers",
//	    "notify", "profile", "profiles",
//	    "experimental_realtime_webrtc_call_base_url",
//	    "experimental_realtime_ws_base_url", "otel",
//	];
//
// plus a single special case that strips features.respect_system_proxy.
//
// Of those, cfgaudit reads three: notify (a command site) plus chatgpt_base_url
// and model_providers (CFG071). Reporting them from a project file would be a
// pure false positive — the same reasoning that keeps Devin's user-only
// sandbox.excluded unmodelled.
//
// approval_policy, sandbox_mode, mcp_servers, default_permissions and permissions
// are deliberately NOT on the upstream denylist, which is why CFG063/CFG064 and
// the MCP family do apply to a committed file.
func (c *CodexConfig) ApplyProjectLayerDenylist() {
	if c == nil {
		return
	}
	c.Notify = nil
	c.ChatGPTBaseURL = ""
	c.ModelProviders = nil
}
