// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg057 struct{}

var CFG057 = &cfg057{}

func init() { All = append(All, CFG057) }

func (r *cfg057) ID() string { return "CFG057" }

var (
	// dataURIRe matches a real data: URI (mediatype + payload), which has no place
	// in a trusted instruction file and can smuggle a hidden/encoded payload.
	dataURIRe = mustFiltered(`(?i)\bdata:([a-z]+/[a-z0-9.+-]+)[a-z0-9;=-]*,([^\s"')]{16,})`)
	// inertImageTypes are raster image types: their payload is pixels, which
	// the model does not read as an instruction. SVG stays reported, since it
	// can carry script and text (#1216).
	inertImageTypes = map[string]bool{"image/png": true, "image/jpeg": true, "image/jpg": true, "image/gif": true, "image/webp": true}
	// dataPlaceholderRe matches a payload that is a template slot or a
	// truncated example rather than data: "<base64-encoded-svg>",
	// "PHN2Zy...(full string)" (#1216). The note may use fullwidth
	// parentheses, and the payload match stops at ")" or a space, so the note
	// is often cut short.
	dataPlaceholderRe = regexp.MustCompile(`^<[^<>]*>$|(?:\.{3}|\x{2026})(?:[(\x{FF08}][^)\x{FF09}]*[)\x{FF09}]?)?$`)
	// base64RunRe matches a base64 run that could carry an encoded payload. The
	// length floor only bounds decode attempts; the malicious-content gate (not
	// length) is what keeps false positives low, so a modest floor is fine.
	base64RunRe = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)
	// suspiciousDecodedRe matches command/exfiltration indicators in decoded text,
	// complementing the CFG026 injection-phrase patterns reused below.
	suspiciousDecodedRe = regexp.MustCompile(`(?i)(system prompt|\bexfiltrat|curl\s+[^|]*\|\s*(?:sh|bash)|\bwget\s|/etc/(?:passwd|shadow)|~/\.(?:ssh|aws)|\beval\(|\brm\s+-rf\b|base64\s+-d)`)
)

// Check flags encoded payloads in instruction content that evade CFG024 (invisible
// Unicode) and CFG026 (plaintext phrases): a data: URI, or a long base64 blob that
// decodes to a prompt-injection phrase or command/exfiltration indicator. Decoding
// and matching against known-malicious content keeps this high-signal — a random
// base64 sample in docs does not decode to "ignore previous instructions".
func (r *cfg057) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		add := func(line int, msg string) {
			findings = append(findings, finding.Finding{
				RuleID: "CFG057", Severity: finding.Warn, File: src.File,
				Line: line, Col: 1, Message: src.Name + " line " + strconv.Itoa(line) + " " + msg + userScopeNote(t),
			})
		}

		for i, line := range strings.Split(src.Content, "\n") {
			lineNo := i + 1
			if reportableDataURI(line) {
				add(lineNo, "contains a data: URI — a trusted instruction file should not embed an inline data payload; it can smuggle hidden/encoded content. Remove it")
				continue
			}
			for _, b64 := range base64RunRe.FindAllString(line, -1) {
				if decoded, ok := decodeBase64(b64); ok && decodedLooksMalicious(decoded) {
					add(lineNo, "contains a base64 payload that decodes to instruction/command content — an encoded prompt-injection or command that evades plaintext scanning. Remove it")
					break
				}
			}
		}
	}
	return findings
}

// reportableDataURI reports whether line holds a data: URI that can carry
// content the model reads: not a raster image, and not a placeholder or a
// truncated example (#1216).
func reportableDataURI(line string) bool {
	if !dataURIRe.MatchString(line) {
		return false
	}
	for _, m := range dataURIRe.FindAllStringSubmatch(line, -1) {
		if inertImageTypes[strings.ToLower(m[1])] || dataPlaceholderRe.MatchString(m[2]) {
			continue
		}
		return true
	}
	return false
}

// decodeBase64 tries to decode a base64 run (with or without padding) and returns
// the result only when it is mostly-printable text (not binary like a key/cert).
func decodeBase64(s string) (string, bool) {
	raw := strings.TrimRight(s, "=")
	b, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(b) < 12 {
		return "", false
	}
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	if float64(printable)/float64(len(b)) < 0.85 {
		return "", false // binary payload (key/cert/blob), not encoded text
	}
	return string(b), true
}

// decodedLooksMalicious reports whether decoded text contains a known injection
// phrase (reusing the CFG026 patterns) or a command/exfiltration indicator.
func decodedLooksMalicious(s string) bool {
	for _, p := range bypassPatterns {
		if p.re.MatchString(s) {
			return true
		}
	}
	return suspiciousDecodedRe.MatchString(s)
}
