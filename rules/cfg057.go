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
	dataURIRe = regexp.MustCompile(`(?i)\bdata:[a-z]+/[a-z0-9.+-]+[a-z0-9;=-]*,[^\s"')]{16,}`)
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
	if t == nil || t.InstructionContent == "" {
		return nil
	}
	var findings []finding.Finding
	add := func(line int, msg string) {
		findings = append(findings, finding.Finding{
			RuleID: "CFG057", Severity: finding.Warn, File: t.InstructionFile,
			Line: line, Col: 1, Message: t.instructionName() + " line " + strconv.Itoa(line) + " " + msg + userScopeNote(t),
		})
	}

	for i, line := range strings.Split(t.InstructionContent, "\n") {
		lineNo := i + 1
		if dataURIRe.MatchString(line) {
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
	return findings
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
