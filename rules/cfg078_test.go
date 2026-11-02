// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG078_ReadsCredentialStore(t *testing.T) {
	for _, cmd := range []string{
		// macOS Keychain CLI
		"security find-generic-password -ga login -w",
		"security find-internet-password -s github.com -w",
		"security dump-keychain -d login.keychain",
		"security export -k login.keychain -o /tmp/k",
		// Linux Secret Service
		"secret-tool lookup service github",
		"secret-tool search --all account foo",
		// system password DB
		"getent shadow root",
		"sudo cat /etc/shadow",
		// keychain / keyring files on disk
		"cp ~/Library/Keychains/login.keychain-db /tmp/x",
		"tar czf /tmp/k.tgz ~/.local/share/keyrings",
		// browser saved-credential DBs
		"sqlite3 ~/.config/google-chrome/Default/Login\\ Data \"SELECT * FROM logins\"",
		"cp ~/.mozilla/firefox/abc.default/logins.json /tmp/l",
		"strings ~/.mozilla/firefox/abc.default/key4.db",
	} {
		f := CFG078.Check(hookTarget(t, cmd))
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("expected 1 Error for %q, got %+v", cmd, f)
		}
	}
}

func TestCFG078_Benign_NoFinding(t *testing.T) {
	for _, cmd := range []string{
		// not the macOS security tool
		"security-scan --run ./src",
		// storing a secret, not reading
		"secret-tool store --label=x service foo account bar",
		// world-readable passwd, not the shadow DB
		"cat /etc/passwd",
		// unrelated sqlite / app file
		"sqlite3 ./app.db \"SELECT 1\"",
		"cat ./data/history.json",
	} {
		if f := CFG078.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", cmd, f)
		}
	}
}

func TestCFG078_ScansHelperCommands(t *testing.T) {
	f := CFG078.Check(settingsTarget(t, `{"apiKeyHelper":"security find-generic-password -s anthropic -w"}`))
	if len(f) != 1 {
		t.Fatalf("expected CFG078 on apiKeyHelper helper, got %+v", f)
	}
}

func TestCFG078_NoSettings_NoFinding(t *testing.T) {
	if f := CFG078.Check(&Target{}); len(f) != 0 {
		t.Errorf("expected no finding without settings, got %+v", f)
	}
}

// Without -w or -g, find-*-password prints only attributes: an existence
// check (#1366).
func TestCFG078_ExistenceCheck_NoFinding(t *testing.T) {
	for _, cmd := range []string{
		`if security find-generic-password -a "$USER" -s "${PREFIX}${key}" >/dev/null 2>&1; then echo ok; fi`,
		`security find-internet-password -s github.com -G web >/dev/null`,
	} {
		if f := CFG078.Check(hookTarget(t, cmd)); len(f) != 0 {
			t.Errorf("%q: expected no finding, got %+v", cmd, f)
		}
	}
	for _, cmd := range []string{
		"security find-generic-password -s svc -w",
		"security find-internet-password -gs example.com",
		"security find-generic-password -wa me",
	} {
		if f := CFG078.Check(hookTarget(t, cmd)); len(f) != 1 {
			t.Errorf("%q: expected 1 finding, got %d", cmd, len(f))
		}
	}
}
