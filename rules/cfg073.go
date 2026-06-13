package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg073 struct{}

var CFG073 = &cfg073{}

func init() { All = append(All, CFG073) }

func (r *cfg073) ID() string { return "CFG073" }

// ethPrivateKeyRe matches a 32-byte hex Ethereum private key with the 0x prefix.
// The format is deterministic (0x + exactly 64 hex digits), so a full-string match
// is effectively zero false-positive. A 64-hex string *without* 0x is left alone:
// that shape collides with SHA-256 digests, git SHAs in long form, and other
// non-secret hex blobs, so the prefix is what makes this a credential signal.
var ethPrivateKeyRe = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)

// bip39PhraseLengths are the valid BIP-39 mnemonic word counts (CS = ENT/32 bits
// of checksum over 128–256 bits of entropy → 12/15/18/21/24 words).
var bip39PhraseLengths = map[int]bool{12: true, 15: true, 18: true, 21: true, 24: true}

// Check flags a config value that is a live cryptocurrency signing credential —
// an Ethereum private key or a BIP-39 seed phrase. Unlike a provider API token
// (CFG007/CFG050) these CANNOT be rotated: whoever reads one controls the wallet
// permanently, and a seed phrase derives every account in the HD tree. CFG054's
// entropy heuristic misses both (a 0x-hex key is <3 character classes; a mnemonic
// is low-entropy English words), so this is a dedicated, name-agnostic value scan
// over the same surface: settings.json env and every MCP server's env/headers.
func (r *cfg073) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	emit := func(loc, file, kind string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG073",
			Severity: finding.Error,
			File:     file,
			Message: loc + " contains a hardcoded " + kind +
				" — a cryptocurrency signing credential cannot be rotated: anyone who reads it controls the wallet permanently and irrecoverably. Remove it and reference a shell variable instead" +
				userScopeNote(t),
		})
	}

	scan := func(loc, file, value string) {
		if kind, ok := matchCryptoCredential(value); ok {
			emit(loc, file, kind)
		}
	}

	if t.Settings != nil {
		for _, k := range sortedKeys(t.Settings.Env) {
			scan("env."+k, t.SettingsFile, t.Settings.Env[k])
		}
	}
	for _, ref := range t.mcpServerRefs() {
		base := "mcpServers." + ref.Name
		for _, k := range sortedKeys(ref.Server.Env) {
			scan(base+".env."+k, ref.File, ref.Server.Env[k])
		}
		for _, k := range sortedKeys(ref.Server.Headers) {
			scan(base+".headers."+k, ref.File, ref.Server.Headers[k])
		}
	}
	return findings
}

// matchCryptoCredential reports the kind of cryptocurrency credential value is, if
// any. A runtime reference/placeholder ($VAR, {{X}}) is never a committed secret.
func matchCryptoCredential(value string) (string, bool) {
	v := strings.TrimSpace(value)
	if v == "" || isSecretReference(v) {
		return "", false
	}
	if ethPrivateKeyRe.MatchString(v) {
		return "Ethereum private key", true
	}
	if isBIP39Mnemonic(v) {
		return "BIP-39 seed phrase", true
	}
	return "", false
}

// isBIP39Mnemonic reports whether v is a whitespace-separated run of 12/15/18/21/24
// tokens where every token is a word in the BIP-39 English wordlist. The chance of
// that many arbitrary English words all landing in the fixed 2048-word list is
// negligible, so a match is treated as a real seed phrase.
func isBIP39Mnemonic(v string) bool {
	fields := strings.Fields(strings.ToLower(v))
	if !bip39PhraseLengths[len(fields)] {
		return false
	}
	for _, w := range fields {
		if _, ok := bip39Words[w]; !ok {
			return false
		}
	}
	return true
}
