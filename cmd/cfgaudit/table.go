package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

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
func renderTable(w io.Writer, findings []finding.Finding, version string) {
	if len(findings) == 0 {
		_, _ = fmt.Fprintf(w, "cfgaudit %s — no findings\n", version)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SEVERITY\tRULE\tLOCATION\tMESSAGE")
	for _, f := range findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.RuleID, loc, truncateRunes(tableMessage(f.Message), 80))
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
