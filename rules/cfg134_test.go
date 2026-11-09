// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// #1055: what a committed .pi/ folder adds to the one trust decision.
func TestCFG134(t *testing.T) {
	tg := &Target{
		Scope:  finding.ScopeProject,
		PiFile: ".pi/settings.json",
		Pi: &parser.PiSettings{
			ShellPath:           []byte(`"/tmp/sh"`),
			ShellCommandPrefix:  []byte(`"source env.sh;"`),
			NpmCommand:          []byte(`["pnpm"]`),
			Packages:            []byte(`["npm:a", "npm:b@1.0.0", "./in", "~/out", "../pkgs/x", "../../up"]`),
			Extensions:          []byte(`["./ext.ts"]`),
			DefaultProjectTrust: []byte(`"always"`),
		},
		PiExtensions:  []string{".pi/extensions/a.ts"},
		PiMCPCommands: []parser.PiBangCommand{{Server: "s", Field: "env", Key: "T", Command: "gh auth token"}},
		PiMCPFile:     ".pi/mcp.json",
		PiSystemFile:  ".pi/SYSTEM.md",
	}
	got := CFG134.Check(tg)
	var sev []string
	for _, f := range got {
		sev = append(sev, string(f.Severity)+":"+strings.SplitN(f.Message, " ", 3)[1])
	}
	want := "warn:shellPath warn:shellCommandPrefix warn:npmCommand warn:packages info:packages warn:packages warn:packages warn:extensions info:defaultProjectTrust warn:extension warn:mcp.json info:.pi/SYSTEM.md"
	if strings.Join(sev, " ") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(sev, " "), want)
	}
	if CFG134.Check(nil) != nil || CFG134.Check(&Target{}) != nil {
		t.Error("empty target")
	}
	sites := commandSites(tg)
	var labels []string
	for _, s := range sites {
		labels = append(labels, s.Label)
	}
	if strings.Join(labels, ";") != "pi shellCommandPrefix;pi npmCommand;pi mcp.json server \"s\" env.T `!` command" {
		t.Errorf("sites: %v", labels)
	}
}
