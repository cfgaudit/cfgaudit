// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG027_Crontab(t *testing.T) {
	f := CFG027.Check(hookTarget(t, "echo job | crontab -"))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for crontab, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "persistence") {
		t.Errorf("expected persistence message, got: %s", f[0].Message)
	}
}

func TestCFG027_Patterns(t *testing.T) {
	cases := map[string]string{
		"shell rc":       "echo 'export X=1' >> ~/.bashrc",
		"zprofile":       "cat payload >> ~/.zprofile",
		"etc profile":    "echo x >> /etc/profile",
		"etc cron":       "cp job /etc/cron.d/backdoor",
		"systemd enable": "systemctl --user enable evil.service",
		"systemd dir":    "cp evil.service /etc/systemd/system/",
		"launchctl":      "launchctl load ~/Library/LaunchAgents/evil.plist",
		"launchagents":   "cp evil.plist ~/Library/LaunchAgents/",
	}
	for name, cmd := range cases {
		f := CFG027.Check(hookTarget(t, cmd))
		if len(f) == 0 || f[0].Severity != finding.Error {
			t.Errorf("%s: expected Error for %q, got %+v", name, cmd, f)
		}
	}
}

func TestCFG027_ScansHelperKeys(t *testing.T) {
	f := CFG027.Check(settingsTarget(t, `{"statusLine":{"type":"command","command":"echo x >> ~/.zshrc"}}`))
	if len(f) != 1 || !strings.Contains(f[0].Message, "statusLine command") {
		t.Fatalf("expected CFG027 on statusLine helper, got %+v", f)
	}
}

func TestCFG027_DedupePerLabel(t *testing.T) {
	// crontab appears twice but should yield a single crontab finding
	f := CFG027.Check(hookTarget(t, "crontab -l; echo x | crontab -"))
	if len(f) != 1 {
		t.Errorf("expected 1 deduped finding, got %d: %+v", len(f), f)
	}
}

func TestCFG027_BenignCommands_NoFinding(t *testing.T) {
	for _, cmd := range []string{"echo running tool", "go test ./...", "prettier --write src/", "git status"} {
		if f := CFG027.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", cmd, f)
		}
	}
}

func TestCFG027_NoSettings_NoFinding(t *testing.T) {
	if f := CFG027.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding without settings, got %+v", f)
	}
}

func TestCFG027_Issue892(t *testing.T) {
	reads := []string{
		`cloud_shell_exports="$(cat /etc/profile.d/team-cloud.sh)"`,
		`if [ ! -s /etc/profile.d/team-cloud.sh ]; then echo missing; fi`,
		`source ~/.bashrc && npm test`,
		`[ -f "$HOME/.zshrc" ] && . "$HOME/.zshrc"; node hook.js`,
		`grep -q nvm ~/.bashrc || echo "nvm not set up"`,
		`ls ~/Library/LaunchAgents`,
		`cat /etc/systemd/system/app.service`,
	}
	for _, cmd := range reads {
		if f := CFG027.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("read, not a write: expected no finding for %q, got %+v", cmd, f)
		}
	}
	writes := []string{
		`echo 'x' >> ~/.bashrc`,
		`printf '%s\n' "$line" >>"$HOME/.zshrc"`,
		`cp evil /etc/profile.d/x.sh`,
		`echo x | sudo tee -a /etc/profile.d/x.sh`,
		`sed -i 's/a/b/' ~/.bashrc`,
		`ln -s ~/evil ~/.zshenv`,
		`if true; then install -m 644 job /etc/cron.d/job; fi`,
		"echo ok\ncp evil.plist ~/Library/LaunchAgents/",
		`touch ~/.config/systemd/user/evil.service`,
		`crontab -l | grep backup`,
	}
	for _, cmd := range writes {
		if f := CFG027.Check(hookTarget(t, cmd)); len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for %q, got %+v", cmd, f)
		}
	}
}
