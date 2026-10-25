// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

// Package color decides whether the text and table output use ANSI colour and
// applies it (#925).
package color

import (
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
)

// Enabled reports whether output to w should be coloured. In order:
// --no-color or NO_COLOR (any value) turn colour off; FORCE_COLOR or
// CLICOLOR_FORCE set to anything but "" or "0" turn it on; otherwise it is on
// only when w is a terminal.
func Enabled(noColor bool, w io.Writer) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	if forced("FORCE_COLOR") || forced("CLICOLOR_FORCE") {
		return true
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func forced(env string) bool {
	v := os.Getenv(env)
	return v != "" && v != "0"
}

// Severity colours a severity name: error red, warn yellow, info cyan.
func Severity(s string) string {
	switch s {
	case "error":
		return red + s + reset
	case "warn":
		return yellow + s + reset
	case "info":
		return cyan + s + reset
	}
	return s
}

// Bold wraps s in bold.
func Bold(s string) string { return bold + s + reset }

var (
	// A text line: "<file>[:line:col] [<severity>] <RULE>: <message>".
	textLineRe = regexp.MustCompile(`^(.*? )\[(error|warn|info)\] (CFG[0-9]{3}):`)
	// A table row: the severity, padded, then the rule ID.
	tableRowRe = regexp.MustCompile(`^(error|warn|info)( +)(CFG[0-9]{3})`)
)

// TextLine colours the severity and the rule ID of one text-format finding
// line and leaves any other line unchanged.
func TextLine(line string) string {
	m := textLineRe.FindStringSubmatchIndex(line)
	if m == nil {
		return line
	}
	return line[:m[3]] + "[" + Severity(line[m[4]:m[5]]) + "] " + Bold(line[m[6]:m[7]]) + line[m[7]:]
}

// Table colours the severity and rule ID of each row of an already aligned
// table, so the escape codes do not count towards the column widths.
func Table(out string) string {
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if m := tableRowRe.FindStringSubmatchIndex(l); m != nil {
			lines[i] = Severity(l[m[2]:m[3]]) + l[m[4]:m[5]] + Bold(l[m[6]:m[7]]) + l[m[7]:]
		}
	}
	return strings.Join(lines, "\n")
}
