package rules

import (
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

type cfg063 struct{}

var CFG063 = &cfg063{}

func init() { All = append(All, CFG063) }

func (r *cfg063) ID() string { return "CFG063" }

// Check flags an OpenAI Codex CLI config.toml that removes the human from the
// approval loop, in either of two ways.
//
// approval_policy decides how often Codex asks — the Codex analog of Claude
// Code's defaultMode: bypassPermissions (CFG004). "never" never asks the user
// (all commands auto-approved, non-interactive); the deprecated "on-failure"
// auto-approves everything and only escalates on failure.
//
// approvals_reviewer decides *who* answers the prompts that are still raised.
// "auto_review" (legacy alias "guardian_subagent") routes escalated approval
// requests — sandbox escapes, blocked network access, MCP prompts, ARC
// escalations — to a reviewer subagent instead of the person. A committed file
// can therefore look safe on approval_policy and still have nobody watching.
//
// The remediation deliberately names only "on-request". Codex retired the
// "untrusted" policy on 2026-08-19 ("Remove `untrusted` from the CLI,
// configuration schema, and MCP tool interface. Explicit `approval_policy =
// "untrusted"` settings now fail with an actionable error"), so recommending it
// would hand the reader a config that no longer loads. "on-request" is valid
// before and after that change, which is why no version gate is needed here.
// A file that still carries "untrusted" stays unreported: older Codex versions
// accept it, and on a current one the CLI raises its own error.
//
// approvals_reviewer is warn, not error: Codex's own field documentation says it
// "does not disable separate safety checks such as ARC", and the subagent applies
// a risk framework rather than blanket-approving, so it is a weaker claim than
// approval_policy: never. Both findings can fire on one file; that combination is
// the interesting one and each names its own key.
func (r *cfg063) Check(t *Target) []finding.Finding {
	if t == nil || t.Codex == nil {
		return nil
	}
	var findings []finding.Finding
	add := func(sev finding.Severity, msg string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG063",
			Severity: sev,
			Scope:    t.Scope,
			File:     t.CodexFile,
			Message:  msg + userScopeNote(t),
		})
	}

	switch strings.ToLower(strings.TrimSpace(t.Codex.ApprovalPolicy)) {
	case "never":
		add(finding.Error, "Codex approval_policy is \"never\" — commands are auto-approved without ever asking the user, the Codex equivalent of defaultMode: bypassPermissions (CFG004). Use \"on-request\" to keep a human in the loop")
	case "on-failure":
		add(finding.Warn, "Codex approval_policy is \"on-failure\" (deprecated) — all commands are auto-approved and only escalated to the user on failure. Prefer \"on-request\" so actions are approved before they run")
	}

	if t.Codex.UsesAutoReviewer() {
		add(finding.Warn, "Codex approvals_reviewer is \""+strings.TrimSpace(t.Codex.ApprovalsReviewer)+
			"\" — escalated approval requests (sandbox escapes, blocked network access, MCP prompts) go to a reviewer subagent instead of the person, so a committed file can leave approval_policy looking safe with nobody actually watching. Codex's own docs note this does not disable separate safety checks such as ARC. Set it to \"user\", or drop the key, to keep the prompts human-answered")
	}

	// The same decision is spelled three more times inside [apps], where it
	// applies to one connector's prompts rather than the thread's. The root key
	// above is the thread default; these override it per app and per connected
	// account (core/src/connectors.rs mcp_approvals_reviewer_from_layers resolves
	// link, then app, then _default), so a file can leave the root key untouched
	// and still route a connector's prompts away from the person.
	for _, r := range t.Codex.AppReviewers() {
		scope := "this connector's approval prompts"
		switch {
		case r.App == parser.CodexAppsDefaultKey:
			scope = "approval prompts from every connector"
		case r.Link != "":
			scope = "approval prompts from that connected account"
		}
		add(finding.Warn, r.Path+" is \""+r.Value+"\", so "+scope+
			" go to a reviewer subagent instead of the person. This is the per-app spelling of the root approvals_reviewer key, so a file can look safe on the root key and still leave nobody watching here. Set it to \"user\", or drop the key, to keep the prompts human-answered")
	}
	return findings
}
