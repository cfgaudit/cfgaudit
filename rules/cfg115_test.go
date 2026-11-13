// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG115_NoLink(t *testing.T) {
	if f := CFG115.Check(nil); f != nil {
		t.Errorf("nil target gave %+v", f)
	}
	if f := CFG115.Check(&Target{}); f != nil {
		t.Errorf("target without a link gave %+v", f)
	}
}

func TestCFG115_ConfigPathKeepsItsMessage(t *testing.T) {
	f := CFG115.Check(&Target{EscapedLink: ".mcp.json", EscapedTarget: "../../shared/mcp.json"})
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("got %+v", f)
	}
	want := `this path is a symbolic link to "../../shared/mcp.json", outside the scanned repository. An agent that opens it loads a file from the machine that checked the repository out, not from the repository. cfgaudit did not read it and no other rule ran on it. Commit the file itself instead of a link`
	if f[0].Message != want {
		t.Errorf("message changed: %s", f[0].Message)
	}
	f = CFG115.Check(&Target{EscapedLink: ".mcp.json"})
	if len(f) != 1 || !strings.Contains(f[0].Message, "a path outside the repository") {
		t.Errorf("no link text: %+v", f)
	}
}

func TestCFG115_SensitiveTargets(t *testing.T) {
	for _, target := range []string{
		"~/.ssh/authorized_keys", "../../.ssh/id_rsa", "/home/u/.aws/credentials", "~/.gnupg",
		"~/.bashrc", "~/.bash_profile", "~/.zshrc", "../.profile", "~/.zprofile",
		"~/.claude/settings.json", "~/.codex/config.toml", "~/.gemini/settings.json", "~/.cursor/mcp.json",
		"~/.config/claude/x", "/etc/crontab", "/etc/cron.d/job", "/var/spool/cron/root",
		"~/Library/LaunchAgents/x.plist", "~/.npmrc", "~/.gitconfig", "~/.config/git/config",
		"../../repo/.git/config", `..\..\repo\.git\hooks\pre-commit`, "/usr/local/bin/node",
		"~/.local/bin/helper", `C:\Windows\System32\helper.exe`, `%USERPROFILE%\AppData\Local\Microsoft\WindowsApps\tool.exe`,
	} {
		f := CFG115.Check(&Target{EscapedLink: "x", EscapedTarget: target, EscapedWalked: true})
		if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "sensitive location") {
			t.Errorf("%s: got %+v", target, f)
		}
	}
	for _, target := range []string{"../shared/notes.txt", "/opt/tool", "~/projects/x", "../my.sshfiles/a", "/usr/share/profile.txt", "../.claudeignore", "../project/bin/helper"} {
		f := CFG115.Check(&Target{EscapedLink: "x", EscapedTarget: target, EscapedWalked: true})
		if len(f) != 1 || f[0].Severity != finding.Warn || strings.Contains(f[0].Message, "sensitive") {
			t.Errorf("%s: got %+v", target, f)
		}
	}
}

func TestCFG115_SensitiveConfigPath(t *testing.T) {
	f := CFG115.Check(&Target{EscapedLink: ".mcp.json", EscapedTarget: "~/.claude/mcp.json"})
	if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "no other rule ran on it") {
		t.Errorf("got %+v", f)
	}
}

func TestCFG115_OtherCheckoutAgentFolder1667(t *testing.T) {
	for _, target := range []string{
		"/Users/dev/repos/proj/.claude/skills", "/home/dev/src/other/.codex/config.toml",
		`C:\Users\dev\code\proj\.cursor\rules`, "~/projects/app/.gemini/settings.json", "../other/.claude/skills",
	} {
		f := CFG115.Check(&Target{EscapedLink: ".claude/skills", EscapedTarget: target, EscapedWalked: true})
		if len(f) != 1 || f[0].Severity != finding.Warn || strings.Contains(f[0].Message, "sensitive") {
			t.Errorf("%s: got %+v", target, f)
		}
	}
	for _, target := range []string{
		"/Users/dev/.claude/settings.json", "/home/dev/.codex", `C:\Users\dev\.cursor\mcp.json`,
		"$HOME/.gemini/settings.json", "/root/.claude", "../../.claude/settings.json",
	} {
		f := CFG115.Check(&Target{EscapedLink: ".claude/skills", EscapedTarget: target, EscapedWalked: true})
		if len(f) != 1 || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "sensitive location") {
			t.Errorf("%s: got %+v", target, f)
		}
	}
}
