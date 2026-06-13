package rules

import (
	"strings"
	"testing"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// a real, valid BIP-39 12-word mnemonic (the canonical all-but-last "abandon" test
// vector with a valid checksum word).
const testMnemonic12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestCFG073_EthKeyInSettingsEnv_Error(t *testing.T) {
	tgt := settingsTarget(t, `{"env":{"PRIVATE_KEY":"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"}}`)
	f := CFG073.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for ETH key, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "Ethereum private key") || !strings.Contains(f[0].Message, "cannot be rotated") {
		t.Errorf("expected ETH-key + non-rotatable message, got %q", f[0].Message)
	}
}

func TestCFG073_EthKeyInMCPEnv_Error(t *testing.T) {
	tgt := settingsTarget(t, `{"mcpServers":{"wallet":{"command":"npx","args":["-y","mcp-wallet-server"],"env":{"PK":"0xAC0974BEC39A17E36BA4A6B4D238FF944BACB478CBED5EFCAE784D7BF4F2FF80"}}}}`)
	f := CFG073.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for ETH key in MCP env, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "mcpServers.wallet.env.PK") {
		t.Errorf("expected MCP-env location, got %q", f[0].Message)
	}
}

func TestCFG073_Mnemonic_Error(t *testing.T) {
	tgt := settingsTarget(t, `{"env":{"SEED_PHRASE":"`+testMnemonic12+`"}}`)
	f := CFG073.Check(tgt)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 Error for mnemonic, got %+v", f)
	}
	if !strings.Contains(f[0].Message, "BIP-39 seed phrase") {
		t.Errorf("expected BIP-39 message, got %q", f[0].Message)
	}
}

func TestCFG073_Mnemonic24Words_Error(t *testing.T) {
	phrase := testMnemonic12 + " " + testMnemonic12 // 24 valid BIP-39 words
	tgt := settingsTarget(t, `{"env":{"WALLET":"`+phrase+`"}}`)
	if f := CFG073.Check(tgt); len(f) != 1 {
		t.Fatalf("expected 1 Error for 24-word phrase, got %+v", f)
	}
}

func TestCFG073_Benign_NoFinding(t *testing.T) {
	for _, cfg := range []string{
		`{"env":{"PRIVATE_KEY":"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff"}}`,    // 62 hex — wrong length
		`{"env":{"HASH":"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"}}`,            // 64 hex, no 0x prefix (digest-shaped)
		`{"env":{"KEY":"$WALLET_KEY"}}`,                                                                  // shell reference
		`{"env":{"KEY":"${SEED}"}}`,                                                                      // shell reference
		`{"env":{"NOTE":"the quick brown fox jumps over the lazy dog while you watch them all run"}}`,    // 14 English words, not all BIP-39, wrong count
		`{"env":{"MSG":"abandon ability able about above absent absorb abstract absurd abuse access"}}`,  // 11 BIP-39 words — not a valid length
		`{"env":{"PLAIN":"hello world"}}`,                                                                // short
	} {
		if f := CFG073.Check(settingsTarget(t, cfg)); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %+v", cfg, f)
		}
	}
}

func TestCFG073_UserScopeNote(t *testing.T) {
	tgt := settingsTarget(t, `{"env":{"PK":"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"}}`)
	tgt.Scope = finding.ScopeUser
	f := CFG073.Check(tgt)
	if len(f) != 1 || !strings.Contains(f[0].Message, "every project you open") {
		t.Fatalf("expected user-scope note, got %+v", f)
	}
}

func TestCFG073_NilTarget(t *testing.T) {
	if f := CFG073.Check(nil); f != nil {
		t.Errorf("expected nil for nil target, got %+v", f)
	}
}

func TestBIP39WordlistIntegrity(t *testing.T) {
	if got := len(bip39Words); got != 2048 {
		t.Errorf("BIP-39 wordlist has %d words, want 2048", got)
	}
	for _, w := range []string{"abandon", "zoo", "about", "zone"} {
		if _, ok := bip39Words[w]; !ok {
			t.Errorf("expected %q in BIP-39 wordlist", w)
		}
	}
	if _, ok := bip39Words["notabip39word"]; ok {
		t.Error("unexpected word in BIP-39 wordlist")
	}
}
