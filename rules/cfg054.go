// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
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
			if hit, sub := looksLikeSecretEntropy(k, t.Settings.Env[k]); hit {
				emit("env."+k+sub, t.SettingsFile)
			}
		}
	}
	for _, ref := range t.mcpServerRefs() {
		base := "mcpServers." + ref.Name
		for _, k := range sortedKeys(ref.Server.Env) {
			if hit, sub := looksLikeSecretEntropy(k, ref.Server.Env[k]); hit {
				emit(base+".env."+k+sub, ref.File)
			}
		}
		for _, k := range sortedKeys(ref.Server.Headers) {
			if _, reported := headerCredential(k, ref.Server.Headers[k]); reported {
				continue // CFG050 reports it (#1053)
			}
			if hit, sub := looksLikeSecretEntropy(k, ref.Server.Headers[k]); hit {
				emit(base+".headers."+k+sub, ref.File)
			}
		}
	}
	return findings
}

// looksLikeSecretEntropy applies the conservative gates described on Check.
//
// A value that holds a JSON object or array is not scored as one token: the
// quotes, braces and colon inflate its character classes and its entropy, so a
// harmless header blob reads like a secret. The parsed value is walked instead
// and every string leaf is gated on its own, keyed by its JSON path.
//
// The second return value is the path of the offending leaf inside the JSON
// value ("" when the whole value is the offender), so the finding can point at
// the leaf rather than the whole blob.
func looksLikeSecretEntropy(key, value string) (bool, string) {
	v := strings.TrimSpace(value)
	if leaves, ok := jsonStringLeaves(v); ok {
		for _, leaf := range leaves {
			// Gate the leaf on the outer env/header name, not on the leaf's own
			// JSON key: CFG007/CFG050 only ever see the outer name, so a leaf
			// under a *_TOKEN/_SECRET/_PASSWORD key would otherwise go
			// unreported.
			if leafLooksLikeSecret(key, leaf.value) {
				return true, leaf.path
			}
		}
		return false, ""
	}
	return leafLooksLikeSecret(key, v), ""
}

// jsonLeaf is a string leaf of a JSON object or array value.
type jsonLeaf struct {
	// path locates the leaf inside the parsed value, e.g. ".User-Agent" or
	// ".items[0]".
	path string
	// value is the leaf's string content.
	value string
}

// jsonStringLeaves parses value as a JSON object or array and returns its
// string leaves. ok is false when value is not a JSON object or array.
func jsonStringLeaves(value string) ([]jsonLeaf, bool) {
	v := strings.TrimSpace(value)
	if !strings.HasPrefix(v, "{") && !strings.HasPrefix(v, "[") {
		return nil, false
	}
	var decoded any
	if err := json.Unmarshal([]byte(v), &decoded); err != nil {
		return nil, false
	}
	var leaves []jsonLeaf
	var walk func(node any, path string)
	walk = func(node any, path string) {
		switch n := node.(type) {
		case map[string]any:
			keys := make([]string, 0, len(n))
			for k := range n {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(n[k], path+"."+k)
			}
		case []any:
			for i, child := range n {
				walk(child, fmt.Sprintf("%s[%d]", path, i))
			}
		case string:
			leaves = append(leaves, jsonLeaf{path: path, value: n})
		}
	}
	walk(decoded, "")
	return leaves, true
}

// leafLooksLikeSecret applies the conservative gates described on Check to a
// single value.
func leafLooksLikeSecret(key, value string) bool {
	v := strings.TrimSpace(value)
	if len(v) < entropyMinLen {
		return false
	}
	// Leave the known cases to CFG007/CFG050 (no double-reporting).
	if secretKeyName(key) {
		return false
	}
	if _, ok := envHeaders(key, v); ok {
		return false // a header list, checked header by header by CFG007
	}
	if _, ok := matchSecretPattern(v); ok {
		return false
	}
	if jwtRe.MatchString(v) {
		return false // not reported above, so a public Supabase anon key (#1053)
	}
	// Structural exemptions: references, placeholders, prose, paths, URLs.
	if isSecretReference(v) || placeholderRe.MatchString(v) {
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
