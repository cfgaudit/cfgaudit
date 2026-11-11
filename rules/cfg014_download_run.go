// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"
)

// downloadStepSplitRe splits a command line into steps at &&, ||, ; and
// newlines (#1686). A pipe stays inside its step.
var downloadStepSplitRe = regexp.MustCompile(`&&|\|\||;|\n`)

// downloadThenRuns reports whether command saves a download to a file and a
// later step runs that file: `curl -o f.sh URL && bash f.sh`, `wget -O f URL;
// sh f`, `curl -o tool URL && chmod +x tool && ./tool`, `Invoke-WebRequest
// -OutFile x.ps1 URL; ./x.ps1` (#1686). A checksum or signature check between
// the download and the run (`sha256sum -c`, `shasum -a 256 -c`, `gpg
// --verify`) keeps it unreported, as for pipes.
func downloadThenRuns(command string) bool {
	downloaded := map[string]bool{}
	executable := map[string]bool{}
	for _, step := range downloadStepSplitRe.Split(command, -1) {
		words := stepWords(step)
		if len(words) == 0 {
			continue
		}
		if target := downloadTarget(words); target != "" {
			downloaded[target] = true
			continue
		}
		if len(downloaded) == 0 {
			continue
		}
		if stepVerifiesChecksum(step) {
			// A verification step checks the downloads before it; sha256sum -c
			// reads the file names from a checksum list, so it need not name them.
			downloaded = map[string]bool{}
			continue
		}
		cmd := strings.ToLower(words[0])
		if cmd == "chmod" {
			for _, w := range words[1:] {
				if downloaded[normPath(w)] {
					executable[normPath(w)] = true
				}
			}
			continue
		}
		switch cmd {
		case "sh", "bash", "zsh", "source", ".", "python", "python3", "node", "pwsh", "powershell":
			if op := firstOperand(words[1:]); op != "" && downloaded[normPath(op)] {
				return true
			}
			continue
		}
		run := words[0]
		if run == "&" && len(words) > 1 {
			run = words[1]
		}
		p := normPath(run)
		if downloaded[p] && (executable[p] || isWindowsScript(p)) && looksLikePath(run) {
			return true
		}
	}
	return false
}

// stepWords splits one step into words, without quotes, after a leading sudo
// or VAR=value assignments.
func stepWords(step string) []string {
	var words []string
	for _, f := range strings.Fields(step) {
		words = append(words, strings.Trim(f, `"'`))
	}
	for len(words) > 0 && (words[0] == "sudo" || (strings.Contains(words[0], "=") && !strings.HasPrefix(words[0], "-"))) {
		words = words[1:]
	}
	return words
}

// downloadTarget returns the file a curl, wget or Invoke-WebRequest step
// saves to: -o/--output (curl, also at the end of a flag cluster such as
// -fsSLo), -O/--output-document (wget), -OutFile (PowerShell) or a `> file`
// redirection. Standard output (`-`) is not a file.
func downloadTarget(words []string) string {
	cmd := strings.ToLower(words[0])
	var curl, wget, ps bool
	switch cmd {
	case "curl", "curl.exe":
		curl = true
	case "wget":
		wget = true
	case "iwr", "invoke-webrequest", "invoke-restmethod", "irm":
		ps = true
	default:
		return ""
	}
	target := ""
	for i := 1; i < len(words); i++ {
		w := words[i]
		next := func() string {
			if i+1 < len(words) {
				i++
				return words[i]
			}
			return ""
		}
		lw := strings.ToLower(w)
		switch {
		case w == ">" || w == ">>":
			target = next()
		case strings.HasPrefix(w, ">") && len(strings.TrimLeft(w, ">")) > 0:
			target = strings.TrimLeft(w, ">")
		case ps && lw == "-outfile":
			target = next()
		case ps && strings.HasPrefix(lw, "-outfile:"):
			target = w[len("-outfile:"):]
		case curl && w == "--output":
			target = next()
		case curl && strings.HasPrefix(w, "--output="):
			target = w[len("--output="):]
		case wget && w == "--output-document":
			target = next()
		case wget && strings.HasPrefix(w, "--output-document="):
			target = w[len("--output-document="):]
		case curl && strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && strings.HasSuffix(w, "o"):
			target = next()
		case wget && strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && strings.HasSuffix(w, "O"):
			target = next()
		}
	}
	if target == "-" || target == "/dev/null" {
		return ""
	}
	return normPath(target)
}

// stepVerifiesChecksum reports whether any command of a step's pipeline
// verifies a checksum, as in `echo "<sha256>  f.sh" | sha256sum -c -`.
func stepVerifiesChecksum(step string) bool {
	for _, part := range strings.Split(step, "|") {
		if words := stepWords(part); len(words) > 0 && verifiesChecksum(words) {
			return true
		}
	}
	return false
}

// verifiesChecksum reports whether a step checks a file against a checksum
// list or a signature.
func verifiesChecksum(words []string) bool {
	cmd := strings.ToLower(words[0])
	has := func(flags ...string) bool {
		for _, w := range words[1:] {
			for _, f := range flags {
				if w == f {
					return true
				}
			}
		}
		return false
	}
	switch cmd {
	case "sha256sum", "sha512sum", "sha1sum", "md5sum", "b2sum", "shasum":
		return has("-c", "--check")
	case "gpg", "gpg2":
		return has("--verify")
	case "cosign":
		return len(words) > 1 && strings.HasPrefix(words[1], "verify")
	}
	return false
}

// firstOperand returns the first argument that is not a flag.
func firstOperand(args []string) string {
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

func normPath(p string) string {
	p = strings.ReplaceAll(strings.Trim(p, `"'`), `\`, "/")
	return strings.TrimPrefix(p, "./")
}

// looksLikePath reports whether a command word is run as a file path rather
// than looked up on PATH: `./tool`, `/tmp/tool`, `.\x.ps1`.
func looksLikePath(w string) bool {
	return strings.ContainsAny(w, `/\`)
}

func isWindowsScript(p string) bool {
	lp := strings.ToLower(p)
	for _, ext := range []string{".ps1", ".cmd", ".bat", ".exe"} {
		if strings.HasSuffix(lp, ext) {
			return true
		}
	}
	return false
}
