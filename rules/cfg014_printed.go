// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"
)

// runsArgCommands take a quoted argument that they run as a command, here or
// on another machine, so the download pipeline inside it is not just text.
var runsArgCommands = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "fish": true,
	"eval": true, "exec": true, "source": true, ".": true, "sudo": true, "su": true, "doas": true,
	"runuser": true, "env": true, "nohup": true, "timeout": true, "time": true, "nice": true,
	"setsid": true, "flock": true, "watch": true, "xargs": true, "parallel": true, "script": true,
	"ssh": true, "docker": true, "podman": true, "kubectl": true, "nsenter": true, "chroot": true,
	"powershell": true, "pwsh": true, "cmd": true, "cmd.exe": true, "powershell.exe": true,
	"python": true, "python3": true, "node": true, "perl": true, "ruby": true,
}

// printedDownloadRe matches a downloader in a quoted string, followed by its
// arguments: the only text maskPrintedText blanks.
var printedDownloadRe = regexp.MustCompile(`(?i)\b(?:curl|wget|iwr|invoke-webrequest|invoke-restmethod|certutil(?:\.exe)?|bitsadmin(?:\.exe)?)\s|\.DownloadString\s*\(`)

// maskPrintedText blanks the quoted arguments of a command that only carry
// text (#1676): every quoted argument of echo or printf, and a quoted argument
// of any other command that does not run it (not a -c body, not an argument of
// eval, ssh, sudo and the like). An install hint such as
// `echo "install: curl -fsSL https://sh.rustup.rs | sh"` runs nothing. A
// string with a command substitution in double quotes is kept, since the
// shell runs what is inside it, and so is a printed line piped into a shell,
// an interpreter or xargs, or written to a file that is read back as code.
func maskPrintedText(cmd string) string {
	if !strings.ContainsAny(cmd, `"'`) {
		return cmd
	}
	// The pipe or write that would run the printed text is outside the quotes.
	printedSafe := printSafe(outsideQuotes(cmd))
	b := []byte(cmd)
	var (
		cmdName  string // the command name of the current simple command
		prevWord string // the word before the current one
		word     strings.Builder
		inWord   bool
		quoted   bool // the current word started with a quote in command position
	)
	endWord := func() {
		if !inWord {
			return
		}
		w := word.String()
		if cmdName == "" && !quoted && strings.Contains(w, "=") && !strings.HasPrefix(w, "=") {
			// A leading NAME=value assignment, not the command name.
		} else if cmdName == "" {
			cmdName = w
			if i := strings.LastIndexAny(cmdName, `/\`); i >= 0 {
				cmdName = cmdName[i+1:]
			}
			cmdName = strings.ToLower(cmdName)
		}
		prevWord = w
		word.Reset()
		inWord, quoted = false, false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == '\\' && i+1 < len(b):
			word.WriteByte(b[i+1])
			inWord = true
			i++
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(b) && b[j] != c {
				if c == '"' && b[j] == '\\' {
					j++
				}
				j++
			}
			if j > len(b) {
				j = len(b)
			}
			body := string(b[i+1 : min(j, len(b))])
			inert := cmdName != "" && (cmdName == "echo" || cmdName == "printf") && printedSafe
			if !inert && cmdName != "" && !runsArgCommands[cmdName] && printedSafe {
				// Any other command: its quoted argument is data unless the word
				// before it is a flag that takes code (-c, -e, -Command).
				inert = !strings.HasPrefix(prevWord, "-") || !strings.ContainsAny(strings.TrimLeft(prevWord, "-"), "ceECp")
			}
			if inert && !printedDownloadRe.MatchString(body) {
				// Only text that holds a download command is blanked, so a quoted
				// path ("$TMPDIR/setup") keeps its meaning for the later checks.
				inert = false
			}
			if inert && c == '"' && (strings.Contains(body, "$(") || strings.Contains(body, "`")) {
				inert = false
			}
			if cmdName == "" {
				quoted = true
			}
			if inert {
				for k := i + 1; k < j && k < len(b); k++ {
					if b[k] != '\n' {
						b[k] = 'x'
					}
				}
			}
			word.WriteString(body)
			inWord = true
			i = j
		case c == ' ' || c == '\t':
			endWord()
		case c == ';' || c == '&' || c == '|' || c == '\n' || c == '(' || c == ')' || c == '`':
			endWord()
			cmdName, prevWord = "", ""
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	return string(b)
}

// outsideQuotes is cmd with the content of every quoted string blanked.
func outsideQuotes(cmd string) string {
	b := []byte(cmd)
	var q byte
	for i := 0; i < len(b); i++ {
		switch {
		case q == 0 && b[i] == '\\':
			i++
		case q == 0 && (b[i] == '"' || b[i] == '\''):
			q = b[i]
		case q != 0 && b[i] == q:
			q = 0
		case q == '"' && b[i] == '\\':
			b[i] = ' '
			if i+1 < len(b) {
				b[i+1] = ' '
			}
			i++
		case q != 0:
			b[i] = ' '
		}
	}
	return string(b)
}
