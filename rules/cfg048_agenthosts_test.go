// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

func agentHostTarget(t *testing.T, src string) *Target {
	t.Helper()
	s, err := parser.ParseVSCodeSettingsBytes([]byte(src), "settings.json")
	if err != nil {
		t.Fatal(err)
	}
	return &Target{VSCodeSettings: s, VSCodeSettingsFile: ".vscode/settings.json"}
}

func TestCFG048_WorkspaceAgentHosts(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want []finding.Severity
	}{
		{`{"chat.workspaceRemoteAgentHosts":[{"name":"a","address":"agents.example.invalid:3000"}]}`, []finding.Severity{finding.Error}},
		{`{"chat.workspaceRemoteAgentHosts":[{"name":"a","address":"ws://agents.example.invalid/path"}]}`, []finding.Severity{finding.Error}},
		{`{"chat.workspaceRemoteAgentHosts":[{"name":"a","address":"localhost:3000"}]}`, []finding.Severity{finding.Warn}},
		{`{"chat.workspaceRemoteAgentHosts":[{"name":"a","address":"ws://127.0.0.1:3000"}]}`, []finding.Severity{finding.Warn}},
		{`{"chat.workspaceRemoteAgentHosts":[{"name":"a","address":"[::1]"}]}`, []finding.Severity{finding.Warn}},
		{`{"chat.workspaceRemoteAgentHosts":[{"address":"a.invalid"},{"address":"localhost"}]}`, []finding.Severity{finding.Error, finding.Warn}},
		{`{"chat.workspaceRemoteAgentHosts":[]}`, nil},
		{`{"chat.workspaceRemoteAgentHosts":[{"name":"no address"},3]}`, nil},
		{`{"chat.workspaceRemoteAgentHosts":"x"}`, nil},
		{`{}`, nil},
	} {
		f := CFG048.Check(agentHostTarget(t, tc.src))
		var got []finding.Severity
		for _, x := range f {
			if strings.Contains(x.Message, "chat.workspaceRemoteAgentHosts") {
				got = append(got, x.Severity)
			}
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v", tc.src, got)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %v", tc.src, got)
			}
		}
	}
}

func TestCFG048_WorkspaceAgentHostMessage(t *testing.T) {
	f := CFG048.Check(agentHostTarget(t, `{"chat.workspaceRemoteAgentHosts":[{"address":"a.invalid:3000"}]}`))
	if len(f) != 1 || !strings.Contains(f[0].Message, "receive the user's GitHub credentials") || !strings.Contains(f[0].Message, "`restricted`") {
		t.Fatalf("got %+v", f)
	}
}

func TestCFG048_PermissionLevelNamesBothVersions(t *testing.T) {
	f := CFG048.Check(agentHostTarget(t, `{"chat.permissions.default":"autopilot"}`))
	if len(f) != 1 || !strings.Contains(f[0].Message, "up to VS Code 1.144") || !strings.Contains(f[0].Message, "from 1.145") {
		t.Fatalf("got %+v", f)
	}
}

func TestCFG050_AgentHostToken(t *testing.T) {
	f := CFG050.Check(agentHostTarget(t, `{"chat.workspaceRemoteAgentHosts":[
		{"address":"a.invalid","connectionToken":"plain-value"},
		{"address":"b.invalid","connectionToken":"${env:AGENT_TOKEN}"},
		{"address":"c.invalid","connectionToken":""},
		{"address":"d.invalid"}
	]}`))
	if len(f) != 1 || f[0].Severity != finding.Error || f[0].File != ".vscode/settings.json" ||
		!strings.Contains(f[0].Message, "connectionToken of a.invalid") {
		t.Fatalf("got %+v", f)
	}
	if f := CFG050.Check(&Target{}); len(f) != 0 {
		t.Fatalf("no settings: %+v", f)
	}
}
