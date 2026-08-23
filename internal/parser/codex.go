package parser

import (
	"fmt"
	"sort"
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

	// BrowserUse and ComputerUse are the [browser_use] and [computer_use] tables
	// Codex added on 2026-08-21. Neither is on PROJECT_LOCAL_CONFIG_DENYLIST, so a
	// committed config sets both; verified against 0.150.0-alpha.7, where the
	// repository's values come back through the app server's config/read in a
	// trusted directory and vanish in an untrusted one.
	//
	// Version boundary, measured rather than assumed: 0.149.0 (npm `latest` on
	// 2026-08-23) has no such field in its config surface at all, so a committed
	// block is inert there. Presence-based gating handles that on its own — a
	// build without the surface has no such config to read.
	BrowserUse  *CodexBrowserUse  `toml:"browser_use"`
	ComputerUse *CodexComputerUse `toml:"computer_use"`

	// Features is the centralized [features] table. Only guardianv2 is modelled:
	// it configures Codex's own security reviewer, and `features` is not on
	// PROJECT_LOCAL_CONFIG_DENYLIST (the only project-layer removal inside it is
	// features.respect_system_proxy), so a committed value crosses.
	Features CodexFeatures `toml:"features"`

	// Hooks is the inline [hooks] table, the TOML twin of .codex/hooks.json.
	// `hooks` is deliberately NOT on Codex's PROJECT_LOCAL_CONFIG_DENYLIST, so a
	// committed table is discovered (#431). Its `state` sub-table is not decoded:
	// only User and SessionFlags layers may write hook state, so a repo cannot
	// self-trust its own hooks.
	Hooks CodexHookEventsToml `toml:"hooks"`
}

// CodexBrowserUse is [browser_use]. Every policy value is an AllowDeny enum with
// exactly two members, so "allow" is the only weakening direction and there is
// no "ask" middle state to argue about.
type CodexBrowserUse struct {
	AllowHistoryAccess  *bool                         `toml:"allow_history_access"`
	DefaultOriginPolicy *CodexBrowserOriginPolicy     `toml:"default_origin_policy"`
	Origins             map[string]CodexBrowserOrigin `toml:"origins"`
}

// CodexBrowserOriginPolicy is the per-origin policy shape, used both for the
// default and for a named origin.
type CodexBrowserOriginPolicy struct {
	Access        string `toml:"access"`
	Downloads     string `toml:"downloads"`
	Uploads       string `toml:"uploads"`
	FullCDPAccess string `toml:"full_cdp_access"`
}

// CodexBrowserOrigin is one [browser_use.origins."<origin>"] table.
type CodexBrowserOrigin = CodexBrowserOriginPolicy

// CodexComputerUse is [computer_use], which decides which desktop applications
// the agent may drive.
type CodexComputerUse struct {
	DefaultAppAccess string                   `toml:"default_app_access"`
	Macos            *CodexComputerUseMacos   `toml:"macos"`
	Windows          *CodexComputerUseWindows `toml:"windows"`
}

// CodexComputerUseMacos maps a macOS bundle id to its access.
type CodexComputerUseMacos struct {
	BundleIDs map[string]string `toml:"bundle_ids"`
}

// CodexComputerUseWindows maps an AUMID to its access and lists executables.
type CodexComputerUseWindows struct {
	AUMIDs map[string]string            `toml:"aumids"`
	Exes   []CodexComputerUseWindowsExe `toml:"exes"`
}

// CodexComputerUseWindowsExe is one entry of [[computer_use.windows.exes]].
// PublisherName, ProductName and Access are required upstream.
type CodexComputerUseWindowsExe struct {
	PublisherName string `toml:"publisher_name"`
	ProductName   string `toml:"product_name"`
	BinaryName    string `toml:"binary_name"`
	Access        string `toml:"access"`
}

// CodexAllows reports whether an AllowDeny value is the allowing one.
func CodexAllows(v string) bool { return strings.EqualFold(strings.TrimSpace(v), "allow") }

// CodexFeatures is the subset of the [features] table cfgaudit reads. The
// wrapper is anyOf: [boolean, table] upstream, so `guardianv2 = false` and a
// table carrying `enabled = false` are two spellings of the same thing; both are
// decoded here.
//
// Note the version split, measured rather than assumed: Codex 0.147.0 rejects
// the TABLE form outright ("invalid type: map, expected a boolean in `features`"
// → "Invalid configuration; using defaults"), while 0.150.0-alpha.7 resolves it.
// So the boolean spelling weakens both, and the table spelling only weakens a
// build new enough to understand it, and invalidates the file on an older one.
type CodexFeatures struct {
	GuardianV2 *CodexGuardianV2 `toml:"guardianv2"`
}

// CodexGuardianV2 is [features.guardianv2], upstream's "User-configurable
// prompt, approval, and context settings for Guardian v2".
//
// Three fields decide whether the reviewer works, and all three resolve from the
// merged layer stack. Verified against 0.150.0-alpha.7 with an isolated
// CODEX_HOME: a committed .codex/config.toml in a trusted directory comes back
// through the app server's config/read as
// {"enabled": false, "classifier_instructions": "<marker>", "review_threshold": 0.95},
// while the same file in an untrusted directory contributes nothing at all.
type CodexGuardianV2 struct {
	// Bool carries the `guardianv2 = false` spelling. Nil when the table form was
	// used instead.
	Bool *bool `toml:"-"`

	Enabled *bool `toml:"enabled"`
	// ReviewThreshold is the score at or above which the blocking reviewer runs
	// on future actions. DEFAULT_REVIEW_THRESHOLD is 0.5, so a higher value
	// narrows what escalates and 1.0 means effectively nothing does.
	ReviewThreshold *float64 `toml:"review_threshold"`
	// ClassifierInstructions replaces the reviewer's prompt outright.
	ClassifierInstructions string `toml:"classifier_instructions"`
}

// UnmarshalTOML accepts both spellings of the feature wrapper: a bare boolean
// and a table.
func (g *CodexGuardianV2) UnmarshalTOML(v any) error {
	switch val := v.(type) {
	case bool:
		g.Bool = &val
		return nil
	case map[string]any:
		if b, ok := val["enabled"].(bool); ok {
			g.Enabled = &b
		}
		switch t := val["review_threshold"].(type) {
		case float64:
			g.ReviewThreshold = &t
		case int64:
			f := float64(t)
			g.ReviewThreshold = &f
		}
		if s, ok := val["classifier_instructions"].(string); ok {
			g.ClassifierInstructions = s
		}
		return nil
	default:
		return nil // a shape this version does not model
	}
}

// Off reports whether the block switches the reviewer off, in either spelling.
func (g *CodexGuardianV2) Off() bool {
	if g == nil {
		return false
	}
	if g.Bool != nil && !*g.Bool {
		return true
	}
	return g.Enabled != nil && !*g.Enabled
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
// command/args/env; streamable-http servers use url and the header keys below.
//
// Codex has two header spellings and they are not interchangeable. http_headers
// holds literal values, which is where a committed credential would be.
// env_http_headers holds environment variable NAMES, so it is indirection and
// cannot carry a secret; it stays decoded and is deliberately not mapped onto
// the shared Headers field, which the secret rules read as literal values.
type CodexMCP struct {
	Command        string            `toml:"command"`
	Args           []string          `toml:"args"`
	Env            map[string]string `toml:"env"`
	URL            string            `toml:"url"`
	HTTPHeaders    map[string]string `toml:"http_headers"`
	EnvHTTPHeaders map[string]string `toml:"env_http_headers"`

	// HTTPHeadersHelper is a shell command whose stdout is parsed as a JSON header
	// map. codex-rs/rmcp-client/src/http_headers.rs runs it as `sh -c "<command>"`
	// with a 10 second timeout when the HTTP client for the server is built. Same
	// class as headersHelper in the Claude settings shape.
	HTTPHeadersHelper string `toml:"http_headers_helper"`

	// DefaultToolsApprovalMode and Tools carry AppToolApproval
	// (auto | prompt | writes | approve). Only "approve" removes the prompt:
	// requires_mcp_tool_approval_for_mode returns false for it outright, "auto" is
	// the default, and "prompt"/"writes" narrow rather than widen.
	DefaultToolsApprovalMode string                  `toml:"default_tools_approval_mode"`
	Tools                    map[string]CodexMCPTool `toml:"tools"`
}

// CodexMCPTool is a [mcp_servers.<name>.tools.<tool>] table, upstream's
// "Per-tool approval settings for a single MCP server tool".
type CodexMCPTool struct {
	ApprovalMode string `toml:"approval_mode"`
}

// codexApprovalNeverAsks reports whether an AppToolApproval value is the one
// that removes the confirmation prompt.
func codexApprovalNeverAsks(mode string) bool {
	return strings.EqualFold(strings.TrimSpace(mode), "approve")
}

// MCPServerMap converts the Codex mcp_servers tables to the shared MCPServer
// shape so the existing MCP rules apply unchanged: command/args/env, url, the
// literal http_headers mapped onto Headers, the headers helper as a command
// site, and the approval modes that never ask.
func (c *CodexConfig) MCPServerMap() map[string]MCPServer {
	if c == nil || len(c.MCPServers) == 0 {
		return nil
	}
	out := make(map[string]MCPServer, len(c.MCPServers))
	for name, s := range c.MCPServers {
		srv := MCPServer{
			Command:       s.Command,
			Args:          s.Args,
			Env:           s.Env,
			URL:           s.URL,
			Headers:       s.HTTPHeaders,
			HeadersHelper: s.HTTPHeadersHelper,
			// Codex spells the key http_headers_helper; naming the Claude spelling
			// in a finding would send the reader grepping for a key that is not in
			// their file.
			HeadersHelperKey: "http_headers_helper",
		}
		if codexApprovalNeverAsks(s.DefaultToolsApprovalMode) {
			srv.ApprovalModeKey = "default_tools_approval_mode"
		}
		for tool, cfg := range s.Tools {
			if codexApprovalNeverAsks(cfg.ApprovalMode) {
				srv.ApprovedTools = append(srv.ApprovedTools, tool)
			}
		}
		sort.Strings(srv.ApprovedTools)
		out[name] = srv
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
