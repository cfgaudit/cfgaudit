// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// #1668: a PostHog project token, placeholders after a vendor prefix and test
// values are not secrets; a real-format token still is.
func TestCFG050_PublishableAndPlaceholders1668(t *testing.T) {
	phc := "phc_" + "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY3zA5bC7dE9fG1h"
	hook := func(cmd string) string {
		b, _ := json.Marshal(map[string]any{"hooks": map[string]any{"SessionStart": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": cmd}}}}}})
		return string(b)
	}
	for _, js := range []string{
		`{"mcpServers":{"ph":{"command":"npx","args":["-y","@posthog/mcp"],"env":{"POSTHOG_API_KEY":"` + phc + `"}}}}`,
		`{"mcpServers":{"ph":{"command":"npx","args":["-y","x","--api-key","` + phc + `"]}}}`,
		hook(`echo "Run: slack auth set xoxb-your-token"`),
		hook(`export GH_TOKEN=local-test && gh api user`),
		hook(`AWS_SECRET_ACCESS_KEY=smoke-not-a-real-key aws s3 ls`),
		hook(`OPENROUTER_API_KEY=sk-or-test-key node x.js`),
		`{"mcpServers":{"s":{"command":"npx","args":["-y","x"],"env":{"SLACK_BOT_TOKEN":"xoxb-your-bot-token-here"}}}}`,
	} {
		if f := CFG050.Check(settingsTarget(t, js)); len(f) != 0 {
			t.Errorf("%s: want no finding, got %+v", js, f)
		}
	}
	ghp := "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"
	for _, js := range []string{
		`{"mcpServers":{"gh":{"command":"npx","args":["-y","x"],"env":{"GITHUB_TOKEN":"` + ghp + `"}}}}`,
		`{"mcpServers":{"gh":{"command":"npx","args":["-y","x"],"env":{"API_TOKEN":"q8Zr2Lw7Vn4Kt1Bm"}}}}`,
		hook(`GH_TOKEN=` + ghp + ` gh api user`),
		hook(`export DEPLOY_API_KEY=contestwinner2024 && deploy`),
	} {
		if f := CFG050.Check(settingsTarget(t, js)); len(f) == 0 || f[0].Severity != finding.Error {
			t.Errorf("%s: want an error, got %+v", js, f)
		}
	}
}

// A secret in a skill's test script is reported at info (#1668); the same
// in the skill's other scripts stays warn.
func TestRun_SkillTestScript1668(t *testing.T) {
	ghp := "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"
	for file, want := range map[string]finding.Severity{
		"skills/x/tests/run.sh":        finding.Info,
		"skills/x/test/run.sh":         finding.Info,
		"skills/x/scripts/test_api.sh": finding.Info,
		"skills/x/scripts/api_test.sh": finding.Info,
		"skills/x/scripts/smoke.sh":    finding.Info,
		"skills/x/scripts/deploy.sh":   finding.Warn,
		"skills/x/scripts/latest.sh":   finding.Warn,
	} {
		tg := &Target{LaunchedScripts: []LaunchedScript{{Label: "script " + file + ",", File: file, Content: "gh api user -H \"Authorization: Bearer " + ghp + "\"\n", Skill: "skills/x/SKILL.md", Shell: true}}}
		var got finding.Severity
		for _, f := range Run(tg, nil, nil) {
			if f.RuleID == "CFG050" {
				got = f.Severity
				if want == finding.Info && !strings.Contains(f.Message, "test script") {
					t.Errorf("%s: message %s", file, f.Message)
				}
			}
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", file, got, want)
		}
	}
}

func TestSkillTestScript_RelError1668(t *testing.T) {
	if skillTestScript("skills/x/SKILL.md", "/abs/tests/run.sh") {
		t.Error("a path that cannot be made relative is not a test script")
	}
}
