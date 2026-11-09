// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"reflect"
	"testing"
)

// #1585: plugins.<id>.apps.<connector> is an apps table of its own, below the
// top-level [apps] and ranked by plugin name.
func TestCodexPluginAppsOverlay1585(t *testing.T) {
	c := parseCodexApps(t, `
[apps.shared]
default_tools_approval_mode = "prompt"

[plugins."alpha@m".apps.tracker]
default_tools_approval_mode = "approve"
approvals_reviewer = "auto_review"

[plugins."alpha@m".apps.tracker.tools.create_issue]
approval_mode = "approve"

[plugins."alpha@m".apps.tracker.links.acct]
default_tools_approval_mode = "approve"
approvals_reviewer = "auto_review"

[plugins."alpha@m".apps._default]
default_tools_approval_mode = "approve"

[plugins."alpha@m".apps.shared]
default_tools_approval_mode = "approve"

[plugins."beta@m".apps.tracker]
default_tools_approval_mode = "approve"

[plugins."beta@m".apps.other.tools.delete_all]
approval_mode = "approve"

[plugins."off@m"]
enabled = false

[plugins."off@m".apps.tracker2]
default_tools_approval_mode = "approve"
`)
	var paths []string
	for _, a := range c.AppApprovals() {
		paths = append(paths, a.Path)
	}
	want := []string{
		`plugins."alpha@m".apps.tracker.default_tools_approval_mode`,
		`plugins."alpha@m".apps.tracker.links.acct.default_tools_approval_mode`,
	}
	if !reflect.DeepEqual(paths, want) {
		t.Errorf("AppApprovals: got %v, want %v", paths, want)
	}

	var tools []string
	for _, a := range c.AppToolApprovals() {
		tools = append(tools, a.Path+":"+a.Tools[0])
	}
	if want := []string{`plugins."alpha@m".apps.tracker.tools:create_issue`, `plugins."beta@m".apps.other.tools:delete_all`}; !reflect.DeepEqual(tools, want) {
		t.Errorf("AppToolApprovals: got %v, want %v", tools, want)
	}

	var reviewers []string
	for _, r := range c.AppReviewers() {
		reviewers = append(reviewers, r.Path)
	}
	if want := []string{`plugins."alpha@m".apps.tracker.approvals_reviewer`, `plugins."alpha@m".apps.tracker.links.acct.approvals_reviewer`}; !reflect.DeepEqual(reviewers, want) {
		t.Errorf("AppReviewers: got %v, want %v", reviewers, want)
	}
}

// A top-level field wins over every plugin overlay, also for a tool and a link.
func TestCodexPluginAppsTopLevelWins1585(t *testing.T) {
	c := parseCodexApps(t, `
[apps.tracker]
approvals_reviewer = "user"

[apps.tracker.tools.create_issue]
approval_mode = "prompt"

[apps.tracker.links.acct]
default_tools_approval_mode = "prompt"
approvals_reviewer = "user"

[plugins."alpha@m".apps.tracker]
approvals_reviewer = "auto_review"

[plugins."alpha@m".apps.tracker.tools.create_issue]
approval_mode = "approve"

[plugins."alpha@m".apps.tracker.links.acct]
default_tools_approval_mode = "approve"
approvals_reviewer = "auto_review"
`)
	if got := c.AppApprovals(); len(got) != 0 {
		t.Errorf("AppApprovals: %+v", got)
	}
	if got := c.AppToolApprovals(); len(got) != 0 {
		t.Errorf("AppToolApprovals: %+v", got)
	}
	if got := c.AppReviewers(); len(got) != 0 {
		t.Errorf("AppReviewers: %+v", got)
	}
	var nilCfg *CodexConfig
	if nilCfg.AppApprovals() != nil || nilCfg.AppToolApprovals() != nil || nilCfg.AppReviewers() != nil {
		t.Error("nil config")
	}
}
