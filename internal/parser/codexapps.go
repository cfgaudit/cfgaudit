package parser

import "sort"

// CodexAppsDefaultKey is the reserved key inside [apps] that carries the
// settings applying to every app. Upstream models it as a distinct type
// (AppsDefaultConfig) with `deny_unknown_fields`, so it accepts only the subset
// of keys an app entry also accepts, and a file that puts `tools` or `links`
// under it does not load at all.
const CodexAppsDefaultKey = "_default"

// CodexApp is one [apps.<id>] table, and also the reserved [apps._default]
// entry: the defaults carry a subset of the same keys, so one shape decodes
// both and the map key alone says which one it is.
//
// Only the approval keys are modelled. `destructive_enabled` and
// `open_world_enabled` look like grants but resolve with `.unwrap_or(true)` at
// both the app and the defaults level, so a committed `true` restates the
// default and only `false` changes anything, in the hardening direction.
// `enabled` and `default_tools_enabled` are capability rather than posture.
type CodexApp struct {
	// ApprovalsReviewer overrides who answers this app's approval prompts.
	ApprovalsReviewer string `toml:"approvals_reviewer"`
	// DefaultToolsApprovalMode is the app-wide (or, under _default, the
	// installation-wide) approval mode for the app's tools.
	DefaultToolsApprovalMode string `toml:"default_tools_approval_mode"`

	// Links is [apps.<id>.links.<link>], upstream's "Per-account approval
	// settings keyed by link ID".
	Links map[string]CodexAppLink `toml:"links"`
	// Tools is [apps.<id>.tools.<tool>], upstream's "Per-tool settings".
	Tools map[string]CodexAppTool `toml:"tools"`
}

// CodexAppLink is one [apps.<id>.links.<link>] table: "Approval settings for a
// connected account within an app".
type CodexAppLink struct {
	ApprovalsReviewer        string `toml:"approvals_reviewer"`
	DefaultToolsApprovalMode string `toml:"default_tools_approval_mode"`
}

// CodexAppTool is one [apps.<id>.tools.<tool>] table.
type CodexAppTool struct {
	ApprovalMode string `toml:"approval_mode"`
}

// CodexAppApproval is one position inside [apps] whose approval mode is the
// value that never asks. Link is empty unless the value sits on a connected
// account; App is CodexAppsDefaultKey for the installation-wide defaults.
type CodexAppApproval struct {
	App  string
	Link string
	Path string
}

// CodexAppToolApprovals collects, for one app, the tool names whose per-tool
// approval_mode never asks.
type CodexAppToolApprovals struct {
	App   string
	Path  string
	Tools []string
}

// CodexAppReviewer is one position inside [apps] that routes approval prompts
// to the reviewer subagent instead of the person.
type CodexAppReviewer struct {
	App   string
	Link  string
	Path  string
	Value string
}

// AppApprovals returns the [apps] positions that cover more than a single tool
// and are set to "approve": the installation-wide default, an app's default,
// and a connected account's default.
//
// The resolution order these sit in is
// managed → tool → link → app → _default → Auto
// (connectors/src/app_tool_policy.rs app_tool_policy_from_apps_config), and
// "approve" is the identity of the restriction lattice in
// AppToolApproval::restrict_to, so it is the one value that never adds an
// approval requirement. Auto is the fallback and is strictly stricter.
//
// Per-tool positions are deliberately not here: they name one tool each, which
// is the distinction the MCP side already draws, so they are returned by
// AppToolApprovals for the same per-tool judgement.
func (c *CodexConfig) AppApprovals() []CodexAppApproval {
	if c == nil || len(c.Apps) == 0 {
		return nil
	}
	var out []CodexAppApproval
	for _, name := range sortedKeys(c.Apps) {
		app := c.Apps[name]
		base := "apps." + name
		if codexApprovalNeverAsks(app.DefaultToolsApprovalMode) {
			out = append(out, CodexAppApproval{
				App:  name,
				Path: base + ".default_tools_approval_mode",
			})
		}
		if name == CodexAppsDefaultKey {
			// A links table under _default makes the file fail to load, so
			// reporting one would name configuration Codex never reads.
			continue
		}
		for _, link := range sortedKeys(app.Links) {
			if codexApprovalNeverAsks(app.Links[link].DefaultToolsApprovalMode) {
				out = append(out, CodexAppApproval{
					App:  name,
					Link: link,
					Path: base + ".links." + link + ".default_tools_approval_mode",
				})
			}
		}
	}
	return out
}

// AppToolApprovals returns the per-app lists of tool names whose approval_mode
// is "approve", so a caller can apply the same per-tool judgement the MCP side
// uses rather than reporting every named tool.
func (c *CodexConfig) AppToolApprovals() []CodexAppToolApprovals {
	if c == nil || len(c.Apps) == 0 {
		return nil
	}
	var out []CodexAppToolApprovals
	for _, name := range sortedKeys(c.Apps) {
		if name == CodexAppsDefaultKey {
			// Same reason as in AppApprovals: _default takes no tools table.
			continue
		}
		app := c.Apps[name]
		var tools []string
		for _, tool := range sortedKeys(app.Tools) {
			if codexApprovalNeverAsks(app.Tools[tool].ApprovalMode) {
				tools = append(tools, tool)
			}
		}
		if len(tools) > 0 {
			out = append(out, CodexAppToolApprovals{
				App:   name,
				Path:  "apps." + name + ".tools",
				Tools: tools,
			})
		}
	}
	return out
}

// AppReviewers returns the [apps] positions that hand approval prompts to the
// reviewer subagent. The chain is link → app → _default
// (core/src/connectors.rs mcp_approvals_reviewer_from_layers), and each position
// is reported on its own because each names a different blast radius.
func (c *CodexConfig) AppReviewers() []CodexAppReviewer {
	if c == nil || len(c.Apps) == 0 {
		return nil
	}
	var out []CodexAppReviewer
	for _, name := range sortedKeys(c.Apps) {
		app := c.Apps[name]
		base := "apps." + name
		if codexAutoReviewer(app.ApprovalsReviewer) {
			out = append(out, CodexAppReviewer{
				App:   name,
				Path:  base + ".approvals_reviewer",
				Value: trimmedCodexValue(app.ApprovalsReviewer),
			})
		}
		if name == CodexAppsDefaultKey {
			continue
		}
		for _, link := range sortedKeys(app.Links) {
			if codexAutoReviewer(app.Links[link].ApprovalsReviewer) {
				out = append(out, CodexAppReviewer{
					App:   name,
					Link:  link,
					Path:  base + ".links." + link + ".approvals_reviewer",
					Value: trimmedCodexValue(app.Links[link].ApprovalsReviewer),
				})
			}
		}
	}
	return out
}

// sortedKeys returns a map's keys in a deterministic order so findings do not
// reshuffle between runs.
func sortedKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
