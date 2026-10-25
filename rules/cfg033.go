// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg033 struct{}

var CFG033 = &cfg033{}

func init() { All = append(All, CFG033) }

func (r *cfg033) ID() string { return "CFG033" }

var (
	// mdImageRe captures the URL of an inline markdown image: ![alt](http(s)://…).
	mdImageRe = regexp.MustCompile(`!\[[^\]]*\]\(\s*(https?://[^)\s]+)\s*\)`)
	// emptyQueryParamRe matches a query parameter with an empty value (name= then
	// & or end) — the LLM is expected to fill it with conversation data.
	emptyQueryParamRe = regexp.MustCompile(`[?&][A-Za-z_][\w.\-]*=(?:&|$)`)
	// urlPlaceholderRe matches a placeholder the LLM might fill: {{…}}, <…>, __…__.
	urlPlaceholderRe = regexp.MustCompile(`\{\{[^}]*\}\}|<[A-Za-z_][^>]*>|__[A-Za-z]\w*__`)
)

// identifierPlaceholderRe matches a placeholder that names an identifier the
// author fills in when writing the link: <uuid>, <NEW_HASH>, <owner>,
// <assets-branch>, <name>, a badge's <status>-<status_color>, and the
// repository facts of a README badge, {{LICENSE}} and {{MAIN_PKG}} (#873). In
// the path of an image URL that is a template for an upload result or a
// repository location, not a slot for conversation data (#856).
var identifierPlaceholderRe = regexp.MustCompile(`(?i)^(?:<|\{\{\s*|__)[\w\-\s]*?(?:uuid|guid|id|hash|sha|owner|org|user(?:name)?|repo(?:sitory)?|branch|tag|version|name|file(?:name)?|path|image|asset|number|slug|width|height|size|status|colou?r|label|style|logo|badge|license|licence|pkg|package|module|project|crate|gem)(?:\s*>|\s*\}\}|__)$`)

// placeholderSink reports whether url has a placeholder the agent could fill
// with conversation data: any placeholder in the query string, or one in the
// path that is not an identifier slot.
func placeholderSink(url string) bool {
	path, query := url, ""
	if i := strings.IndexByte(url, '?'); i >= 0 {
		path, query = url[:i], url[i:]
	}
	if urlPlaceholderRe.MatchString(query) {
		return true
	}
	for _, p := range urlPlaceholderRe.FindAllString(path, -1) {
		if !identifierPlaceholderRe.MatchString(p) {
			return true
		}
	}
	return false
}

// Check flags markdown image references whose URL has an empty or placeholder
// query parameter. Claude is then instructed to fill it with conversation data,
// and rendering/following the image URL exfiltrates that data to the attacker's
// server (the classic markdown-image exfiltration technique).
func (r *cfg033) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	for _, src := range t.instructionSources() {
		for i, line := range strings.Split(src.Content, "\n") {
			for _, m := range mdImageRe.FindAllStringSubmatchIndex(line, -1) {
				url := line[m[2]:m[3]]
				if !emptyQueryParamRe.MatchString(url) && !placeholderSink(url) {
					continue
				}
				lineNo := i + 1
				findings = append(findings, finding.Finding{
					RuleID:   "CFG033",
					Severity: finding.Error,
					File:     src.File,
					Line:     lineNo,
					Col:      m[0] + 1,
					Message: src.Name + " line " + strconv.Itoa(lineNo) + " contains a markdown image with an empty/placeholder query parameter (\"" + url +
						"\") — a data-exfiltration sink: Claude is led to fill the parameter with conversation data, which leaks when the image URL is rendered or fetched. Remove it",
				})
			}
		}
	}
	return findings
}
