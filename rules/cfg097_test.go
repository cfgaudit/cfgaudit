package rules

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
	"github.com/cfgaudit/cfgaudit/internal/parser"
)

// testCredentialLiteral is assembled rather than written inline so gosec does not
// read the test fixture as a real committed credential (G101).
var testCredentialLiteral = "ghp_" + strings.Repeat("a", 20) + "0123456789"

func geminiRemoteTarget(r *parser.GeminiRemoteAgent) *Target {
	return &Target{
		Scope:           finding.ScopeProject,
		InstructionFile: filepath.Join(".gemini", "agents", "helper.md"),
		GeminiRemote:    r,
	}
}

func TestCFG097_CleartextCardURL(t *testing.T) {
	f := CFG097.Check(geminiRemoteTarget(&parser.GeminiRemoteAgent{
		CardURL: "http://agents.example.com/.well-known/agent-card.json",
	}))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "agent_card_url") {
		t.Errorf("message should name the field, got %q", f[0].Message)
	}
}

// Pointing at a remote agent is what the file is for; only the cleartext is the
// finding. A loopback card is served by a local process and is not an exposure.
func TestCFG097_SafeCardURLsSilent(t *testing.T) {
	for _, url := range []string{
		"https://agents.internal.example/.well-known/agent-card.json",
		"http://localhost:8080/.well-known/agent-card.json",
		"http://127.0.0.1:8080/card",
		"",
	} {
		t.Run("url="+url, func(t *testing.T) {
			f := CFG097.Check(geminiRemoteTarget(&parser.GeminiRemoteAgent{CardURL: url}))
			if len(f) != 0 {
				t.Errorf("expected no findings for %q, got %+v", url, f)
			}
		})
	}
}

func TestCFG097_AuthLiteral(t *testing.T) {
	f := CFG097.Check(geminiRemoteTarget(&parser.GeminiRemoteAgent{
		CardURL:     "https://agents.internal.example/card",
		AuthSecrets: map[string]string{"token": testCredentialLiteral},
	}))
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "auth.token") {
		t.Errorf("message should name the field, got %q", f[0].Message)
	}
}

// The docs use $VAR references throughout; those and obvious placeholders must
// not be reported.
func TestCFG097_AuthReferencesSilent(t *testing.T) {
	for name, value := range map[string]string{
		"env reference":     "$MY_TOKEN",
		"braced reference":  "${MY_TOKEN}",
		"template":          "${{ secrets.TOKEN }}",
		"placeholder":       "your-token-here",
		"too short to be a": "abc",
	} {
		t.Run(name, func(t *testing.T) {
			f := CFG097.Check(geminiRemoteTarget(&parser.GeminiRemoteAgent{
				AuthSecrets: map[string]string{"token": value},
			}))
			if len(f) != 0 {
				t.Errorf("expected no findings for %q, got %+v", value, f)
			}
		})
	}
}

// Several credential fields collapse into one finding, named in stable order.
func TestCFG097_MultipleAuthFields(t *testing.T) {
	f := CFG097.Check(geminiRemoteTarget(&parser.GeminiRemoteAgent{
		AuthSecrets: map[string]string{
			"username": "svc-account-prod",
			"password": "hunter2-correct-horse-battery",
		},
	}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "auth.password, auth.username") {
		t.Errorf("fields should be listed in stable order, got %q", f[0].Message)
	}
}

// An inline card marks the file as remote but its contents are not audited.
func TestCFG097_InlineCardAloneSilent(t *testing.T) {
	f := CFG097.Check(geminiRemoteTarget(&parser.GeminiRemoteAgent{HasInlineCard: true}))
	if len(f) != 0 {
		t.Errorf("expected no findings, got %+v", f)
	}
}

func TestCFG097_NoRemoteAgent(t *testing.T) {
	if f := CFG097.Check(&Target{Scope: finding.ScopeProject}); len(f) != 0 {
		t.Errorf("expected no findings, got %+v", f)
	}
	if f := CFG097.Check(nil); len(f) != 0 {
		t.Errorf("expected no findings for a nil target, got %+v", f)
	}
}
