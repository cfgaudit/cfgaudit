package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

func TestCFG007_AnthropicKey(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"ANTHROPIC_API_KEY":"sk-ant-api03-AAAAAAAAAAAAAAAAAAAA"}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "Anthropic API key") {
		t.Errorf("expected message to identify Anthropic key, got: %s", f[0].Message)
	}
}

func TestCFG007_GitHubToken(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"DEPLOY_TOKEN":"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestCFG007_GitLabToken(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"CI_TOKEN":"glpat-xxxxxxxxxxxxxxxxxxxx"}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for GitLab PAT, got %d", len(f))
	}
}

func TestCFG007_AwsAccessKey(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"AWS_ACCESS_KEY_ID":"AKIAIOSFODNN7EXAMPLE"}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for AWS key, got %d", len(f))
	}
}

func TestCFG007_SuspiciousSuffix_LiteralValue(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"JWT_SECRET":"supersecretvalue"}}`))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for *_SECRET key with literal value, got %d", len(f))
	}
}

func TestCFG007_ShellReference_NoFinding(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"JWT_SECRET":"$JWT_SECRET","API_TOKEN":"${API_TOKEN}"}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for shell-variable references, got %d: %+v", len(f), f)
	}
}

func TestCFG007_EmptyValue_NoFinding(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"JWT_SECRET":""}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for empty value, got %d", len(f))
	}
}

func TestCFG007_BenignValue_NoFinding(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"NODE_ENV":"production","DEBUG":"true","HTTP_PORT":"8080"}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding for benign env vars, got %d: %+v", len(f), f)
	}
}

func TestCFG007_MultipleSecrets(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"env":{"ANTHROPIC_API_KEY":"sk-ant-api03-AAAAAAAAAAAAAAAAAAAA","DEPLOY_TOKEN":"glpat-xxxxxxxxxxxxxxxxxxxx"}}`))
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestCFG007_NoEnv_NoFinding(t *testing.T) {
	f := CFG007.Check(settingsTarget(t, `{"permissions":{"allow":["Bash(make *)"]}}`))
	if len(f) != 0 {
		t.Errorf("expected no finding when env absent, got %d", len(f))
	}
}

func TestCFG007_NoSettings_NoFinding(t *testing.T) {
	f := CFG007.Check(&Target{})
	if len(f) != 0 {
		t.Errorf("expected no finding when settings absent, got %d", len(f))
	}
}
