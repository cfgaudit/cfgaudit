// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package cfgaudit

import (
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

var (
	mdFenceRe    = regexp.MustCompile("(?ms)^\\s*(```|~~~).*?^\\s*(```|~~~)")
	mdCodeSpanRe = regexp.MustCompile("`[^`\n]*`")
	mdLinkRe     = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	mdHeadingRe  = regexp.MustCompile(`(?m)^#{1,6}\s+(.+?)\s*#*\s*$`)
	mdAnchorRe   = regexp.MustCompile(`<a\s+(?:id|name)="([^"]+)"`)
)

// TestMarkdownLinks checks every relative link in the tracked Markdown files
// (#804): the file it names exists, and a #fragment names a heading or an
// <a id> in it. The link check workflow covers external URLs but not
// fragments. Fixtures under testdata are scanned input, not docs.
func TestMarkdownLinks(t *testing.T) {
	out, err := exec.Command("git", "ls-files", "-z", "*.md").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	anchors := map[string]map[string]bool{}
	for _, name := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if name == "" || strings.HasPrefix(name, "testdata/") || strings.Contains(name, "/testdata/") {
			continue
		}
		text := stripMarkdownCode(readText(t, name))
		for _, m := range mdLinkRe.FindAllStringSubmatch(text, -1) {
			link := m[1]
			if strings.Contains(link, ":") || strings.HasPrefix(link, "//") {
				continue // a URL scheme (https:, mailto:) or protocol-relative
			}
			file, frag, _ := strings.Cut(link, "#")
			target := name
			if file != "" {
				target = path.Clean(path.Join(path.Dir(name), file))
				if _, err := os.Stat(target); err != nil {
					t.Errorf("%s: link %q: %s does not exist", name, link, target)
					continue
				}
			}
			if frag == "" || !strings.HasSuffix(target, ".md") {
				continue
			}
			if anchors[target] == nil {
				anchors[target] = markdownAnchors(readText(t, target))
			}
			if !anchors[target][strings.ToLower(frag)] {
				t.Errorf("%s: link %q: no heading or <a id> %q in %s", name, link, frag, target)
			}
		}
	}
}

func readText(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name) // #nosec G304 -- names come from git ls-files of this repository
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func stripMarkdownCode(s string) string {
	return mdCodeSpanRe.ReplaceAllString(mdFenceRe.ReplaceAllString(s, ""), "")
}

// markdownAnchors returns the fragments a Markdown file defines: GitHub's slug
// of each heading (with -1, -2 … for repeats) and every <a id="…">.
func markdownAnchors(s string) map[string]bool {
	out := map[string]bool{}
	for _, m := range mdAnchorRe.FindAllStringSubmatch(s, -1) {
		out[strings.ToLower(m[1])] = true
	}
	seen := map[string]int{}
	for _, m := range mdHeadingRe.FindAllStringSubmatch(mdFenceRe.ReplaceAllString(s, ""), -1) {
		slug := githubSlug(m[1])
		if n := seen[slug]; n > 0 {
			out[slug+"-"+strconv.Itoa(n)] = true
		} else {
			out[slug] = true
		}
		seen[slug]++
	}
	return out
}

// githubSlug lowercases a heading, drops everything but letters, digits,
// spaces, hyphens and underscores, and turns spaces into hyphens.
func githubSlug(h string) string {
	h = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`).ReplaceAllString(h, "$1") // link text only
	var b strings.Builder
	for _, r := range strings.ToLower(h) {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}
