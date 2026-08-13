package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// baselineDeny is the hardened default permissions.deny written by `cfgaudit
// init`. The credential/key/cloud/ssh entries are chosen so the generated file
// satisfies cfgaudit's own deny-coverage rules (CFG041–CFG044) with zero
// findings; the Bash entries restrict the destructive/network/privilege command
// classes cfgaudit's command rules flag.
//
// Two anchoring rules drive the shapes here, both measured against Claude Code
// 2.1.231 rather than read off the documentation (#480):
//
//   - A bare `**/` pattern is anchored at the current directory. A project file
//     denying Read(**/.ssh/**) blocks a .ssh directory inside the repository and
//     leaves ~/.ssh readable, which is the file the entry exists for. The `//`
//     prefix anchors at the filesystem root and does cover it. Verified with a
//     marker file in and outside the project: the bare form blocked only the
//     inner path, the `//` form blocked both.
//   - Bash deny matching is a literal prefix. With Bash(echo -n *) denied,
//     `echo -n x` was blocked while `echo -e -n x` and `echo x -n` ran. So a
//     rule naming specific flags is evaded by reordering them, and the command
//     name alone is the only shape that holds.
//
// The location-named entries therefore use `//**/`. The extension-named ones
// (*.pem and friends) stay project-anchored: they name a file kind rather than a
// location, and a repository's own certificates are the case they are about.
var baselineDeny = []string{
	// Credential & key material (CFG041, CFG042, CFG044).
	"Read(**/.env)",
	"Read(**/.env.*)",
	"Read(**/*.pem)",
	"Read(**/*.key)",
	"Read(**/*.p12)",
	"Read(**/*.pfx)",
	"Read(**/*.jks)",
	"Read(//**/.ssh/**)",
	// Cloud credentials (CFG043: AWS, GCP, Azure).
	"Read(//**/.aws/**)",
	"Read(//**/.config/gcloud/**)",
	"Read(//**/.azure/**)",
	// Destructive / network / privilege command classes. `rm` is denied by name
	// rather than by flag, so `rm -fr x` and `rm --recursive --force x` are
	// covered too.
	"Bash(rm *)",
	"Bash(sudo *)",
	"Bash(curl:*)",
	"Bash(wget:*)",
	// Force-push needs four spellings because the flag can sit directly after
	// `push` or at the end of the command, in long or short form. Even these do
	// not make it airtight; per upstream, an argument-constrained Bash rule is
	// guidance. Branch protection is the boundary.
	"Bash(git push --force*)",
	"Bash(git push -f*)",
	"Bash(git push * --force*)",
	"Bash(git push * -f*)",
}

// initOutput implements `cfgaudit init`: scaffold .claude/settings.json with a
// safe-default deny list. stdin is read only in --interactive mode.
func initOutput(args []string, stdin io.Reader) (string, int) {
	dir := "."
	dryRun, force, interactive := false, false, false
	for _, a := range args {
		switch a {
		case "--dry-run":
			dryRun = true
		case "--force":
			force = true
		case "--interactive", "-i":
			interactive = true
		default:
			if strings.HasPrefix(a, "-") {
				return fmt.Sprintf("init: unknown flag %q\n%s", a, initUsage()), 2
			}
			dir = a
		}
	}

	path := filepath.Join(dir, ".claude", "settings.json")
	if !dryRun && !force {
		if _, err := os.Stat(path); err == nil { // #nosec G703 -- path from a user-supplied dir, by design
			return fmt.Sprintf("init: %s already exists; use --force to overwrite or `cfgaudit policy apply` to merge\n", path), 1
		}
	}

	deny := append([]string(nil), baselineDeny...)
	var prompts string
	if interactive {
		extra, msg := collectExtraDenies(stdin, deny)
		prompts = msg
		deny = append(deny, extra...)
	}

	doc := map[string]any{"permissions": map[string]any{"deny": deny}}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Sprintf("init: %v\n", err), 1
	}
	b = append(b, '\n')

	if dryRun {
		return string(b), 0
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil { // #nosec G703 -- dir from a user-supplied path, by design
		return fmt.Sprintf("init: %v\n", err), 1
	}
	if err := os.WriteFile(path, b, 0o600); err != nil { // #nosec G304,G703 -- path from a user-supplied dir, by design
		return fmt.Sprintf("init: %v\n", err), 1
	}
	return prompts + fmt.Sprintf("init: wrote %s with %d deny entries. Review it, then run `cfgaudit %s` to verify.\n", path, len(deny), dir), 0
}

// collectExtraDenies shows the baseline and reads additional deny entries from r,
// one per line, until a blank line or EOF. Returns the new entries (de-duplicated
// against the baseline) and a transcript message for the caller's output.
func collectExtraDenies(r io.Reader, baseline []string) ([]string, string) {
	have := map[string]bool{}
	for _, d := range baseline {
		have[d] = true
	}
	var sb strings.Builder
	sb.WriteString("init: baseline deny list:\n" + bulletList(baseline))
	sb.WriteString("init: enter additional deny entries (one per line, blank line to finish):\n")

	var extra []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			break
		}
		if !have[line] {
			have[line] = true
			extra = append(extra, line)
		}
	}
	return extra, sb.String()
}

func initUsage() string {
	return "Usage:\n" +
		"  cfgaudit init [dir]            # write .claude/settings.json with a safe-default deny list\n" +
		"  cfgaudit init --dry-run [dir]  # print the JSON without writing\n" +
		"  cfgaudit init --interactive    # show the baseline and add project-specific entries\n" +
		"  cfgaudit init --force [dir]    # overwrite an existing settings.json\n"
}
