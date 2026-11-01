// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

// scanFormats are the documented --format values; codequality is an alias
// for codeclimate and stays out of the message.
var scanFormats = []string{"auto", "text", "table", "json", "sarif", "codeclimate"}

// checkFormat rejects a --format value no renderer handles. The output switch
// used to send it to text, so a typo such as "sarfi" in CI wrote a text file
// where a SARIF upload expected JSON (#1050).
func checkFormat(v string) error {
	if v == "codequality" || slices.Contains(scanFormats, v) {
		return nil
	}
	return fmt.Errorf("unknown --format %q; use one of: %s", v, strings.Join(scanFormats, ", "))
}

// resolveFormat turns the --format value into a concrete renderer. "auto" (the
// default) renders a table on an interactive terminal and plain text when stdout
// is a pipe or file, mirroring tools like ls/git that vary output by TTY. Any
// explicit value is passed through unchanged.
func resolveFormat(flagVal string, stdoutIsTTY bool) string {
	if flagVal == "auto" {
		if stdoutIsTTY {
			return "table"
		}
		return "text"
	}
	return flagVal
}

// isTTY reports whether f is connected to an interactive terminal. Uses the
// character-device heuristic so no terminal dependency is needed.
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// renderTable writes findings as an aligned table followed by the summary line.
// Consecutive findings at the same location are grouped: the location is shown
// on the first row only, so one gap reported by several rules (CFG041 to
// CFG044 on one deny list) reads as one block while each rule ID stays on its
// own row for suppression (#1172).
func renderTable(w io.Writer, findings []finding.Finding, version string) {
	if len(findings) == 0 {
		_, _ = fmt.Fprintf(w, "cfgaudit %s — no findings\n", version)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SEVERITY\tRULE\tLOCATION\tMESSAGE")
	prev := ""
	for i, f := range findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		shown := loc
		if i > 0 && loc == prev {
			shown = ""
		}
		prev = loc
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.RuleID, shown, truncateRunes(tableMessage(f.Message), 80))
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintf(w, "\ncfgaudit %s — %d %s\n", version, len(findings), pluralize("finding", len(findings)))
}

// tableMessage shortens a finding message for the table by dropping the
// explanatory tail after the first " — " (the "why/how"), keeping the headline.
func tableMessage(msg string) string {
	if i := strings.Index(msg, " — "); i > 0 {
		return msg[:i]
	}
	return msg
}

// truncateRunes caps s at n runes, appending an ellipsis when it is cut.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
