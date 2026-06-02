package rules

import (
	"math"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg054 struct{}

var CFG054 = &cfg054{}

func init() { All = append(All, CFG054) }

func (r *cfg054) ID() string { return "CFG054" }

const (
	entropyMinLen     = 20  // tokens shorter than this are not flagged
	entropyMinClasses = 3   // distinct character classes (lower/upper/digit/symbol)
	entropyThreshold  = 4.0 // Shannon bits/char; excludes prose, pure hex, UUIDs
)

// Check is the high-entropy fallback to CFG007/CFG050: it flags a config value
// that looks like a random secret token but matches no known vendor pattern and
// sits under an innocuous key name (so the pattern/name rules miss it). It scans
// settings.json env and every MCP server's env/headers. Deliberately conservative
// (warn): a value must have no whitespace, not be a path/url/$VAR/placeholder,
// be >=20 chars, mix >=3 character classes, and exceed the entropy threshold.
func (r *cfg054) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	emit := func(loc, file string) {
		findings = append(findings, finding.Finding{
			RuleID:   "CFG054",
			Severity: finding.Warn,
			File:     file,
			Message: loc + " is a high-entropy value that looks like a hardcoded secret — if it is a credential, reference an environment variable (e.g. \"${TOKEN}\") instead; otherwise ignore" +
				userScopeNote(t),
		})
	}

	if t.Settings != nil {
		for _, k := range sortedKeys(t.Settings.Env) {
			if looksLikeSecretEntropy(k, t.Settings.Env[k]) {
				emit("env."+k, t.SettingsFile)
			}
		}
	}
	for _, ref := range t.mcpServerRefs() {
		base := "mcpServers." + ref.Name
		for _, k := range sortedKeys(ref.Server.Env) {
			if looksLikeSecretEntropy(k, ref.Server.Env[k]) {
				emit(base+".env."+k, ref.File)
			}
		}
		for _, k := range sortedKeys(ref.Server.Headers) {
			if looksLikeSecretEntropy(k, ref.Server.Headers[k]) {
				emit(base+".headers."+k, ref.File)
			}
		}
	}
	return findings
}

// looksLikeSecretEntropy applies the conservative gates described on Check.
func looksLikeSecretEntropy(key, value string) bool {
	v := strings.TrimSpace(value)
	if len(v) < entropyMinLen {
		return false
	}
	// Leave the known cases to CFG007/CFG050 (no double-reporting).
	if hasSecretSuffix(key) {
		return false
	}
	if _, ok := matchSecretPattern(v); ok {
		return false
	}
	// Structural exemptions: references, placeholders, prose, paths, URLs.
	if shellRefRe.MatchString(v) || placeholderRe.MatchString(v) {
		return false
	}
	if strings.ContainsAny(v, " \t\r\n") {
		return false
	}
	if strings.Contains(v, "://") || strings.ContainsAny(v, "/\\") || strings.HasPrefix(v, "~") {
		return false
	}
	if charClasses(v) < entropyMinClasses {
		return false
	}
	return shannonEntropy(v) >= entropyThreshold
}

// charClasses counts how many of {lowercase, uppercase, digit, symbol} appear.
func charClasses(s string) int {
	var lower, upper, digit, symbol bool
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, symbol} {
		if b {
			n++
		}
	}
	return n
}

// shannonEntropy returns the per-character Shannon entropy of s in bits.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}
