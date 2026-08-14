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

// The deny lists `cfgaudit init` can write, smallest first. Each profile is a
// superset of the one before it, so a reader can see exactly what a step up buys.
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

// minimalDeny is credential reads and nothing else. It is the smallest list that
// still satisfies cfgaudit's own deny-coverage rules (CFG006, CFG041–CFG044), so
// a project that wants the file to stay short and reviewable can start here.
var minimalDeny = []string{
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
}

// standardDeny adds what a repository can protect without getting in the way of
// ordinary work: the destructive/network/privilege command classes, the token
// stores the four coverage rules do not name, write protection on the same
// credential paths, and the agent's own config directory.
var standardDeny = append(append([]string(nil), minimalDeny...),
	// Token stores in well-known locations that CFG041–CFG044 do not cover.
	"Read(//**/.netrc)",
	"Read(//**/.npmrc)",
	"Read(//**/.pypirc)",
	"Read(//**/.git-credentials)",
	"Read(//**/.docker/config.json)",
	"Read(//**/.kube/config)",
	"Read(//**/.gnupg/**)",
	// Read is not the only way to abuse a credential path: appending to
	// authorized_keys needs a write, not a read.
	"Edit(//**/.ssh/**)",
	"Edit(//**/.aws/**)",
	"Edit(**/.env)",
	"Edit(**/.env.*)",
	// An agent that may edit .claude/ can remove the deny list constraining it.
	// The same chain CFG047/CFG048 report for another agent's config directory,
	// applied to Claude Code's own.
	"Edit(**/.claude/**)",
	// Destructive / network / privilege command classes. `rm` is denied by name
	// rather than by flag, so `rm -fr x` and `rm --recursive --force x` are
	// covered too.
	"Bash(rm *)",
	"Bash(sudo *)",
	"Bash(su *)",
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
)

// paranoidDeny adds the classes that genuinely close holes but will get in a
// project's way, so they are opt-in rather than default.
//
// The environment runners are the sharpest of them. Claude Code strips a fixed
// set of wrappers before matching (timeout, nice, nohup, command, bare xargs, …)
// but NOT these, and upstream states the consequence directly: "a rule like
// Bash(devbox run *) matches whatever comes after run, including
// devbox run rm -rf .". So every command-class entry above has a documented
// bypass through them, and denying the runner is the only thing a deny list can
// do about it.
//
// PowerShell is a separate tool with its own rules, so none of the Bash entries
// apply to it. Its absence from the shorter profiles is a real gap on Windows
// rather than an oversight.
var paranoidDeny = append(append([]string(nil), standardDeny...),
	// Environment runners: their arguments are a new command no rule sees.
	"Bash(npx *)",
	"Bash(docker exec *)",
	"Bash(direnv exec *)",
	"Bash(devbox run *)",
	"Bash(mise exec *)",
	"Bash(uvx *)",
	// Shell interpreters: any denied command moves into a script and runs there.
	"Bash(sh *)",
	"Bash(bash *)",
	"Bash(zsh *)",
	"Bash(eval *)",
	// Irreversible and outward-facing.
	"Bash(npm publish *)",
	"Bash(terraform apply *)",
	"Bash(terraform destroy *)",
	"Bash(kubectl delete *)",
	"Bash(helm upgrade *)",
	"Bash(docker push *)",
	// The Windows half. PowerShell rules use the same shape as Bash rules.
	"PowerShell(Remove-Item *)",
	"PowerShell(Invoke-Expression *)",
	"PowerShell(Invoke-WebRequest *)",
	"PowerShell(Start-Process *)",
)

// denyProfiles maps the --profile value to its list. `standard` is the default:
// it is a superset of what init wrote before profiles existed, so an existing
// user's `cfgaudit init` does not quietly produce a weaker file.
var denyProfiles = map[string][]string{
	"minimal":  minimalDeny,
	"standard": standardDeny,
	"paranoid": paranoidDeny,
}

// defaultProfile is what `cfgaudit init` writes with no --profile flag.
const defaultProfile = "standard"

// profileNames returns the profile names in increasing order of strictness, for
// usage and error messages.
func profileNames() []string { return []string{"minimal", "standard", "paranoid"} }

// initOutput implements `cfgaudit init`: scaffold .claude/settings.json with a
// safe-default deny list. stdin is read only in --interactive mode.
func initOutput(args []string, stdin io.Reader) (string, int) {
	dir := "."
	dryRun, force, interactive := false, false, false
	profile := defaultProfile
	// Consumed as a queue rather than indexed, so --profile can take its value
	// off the front without index arithmetic the bounds analysis cannot follow.
	for rest := args; len(rest) > 0; {
		a := rest[0]
		rest = rest[1:]
		if name, ok := strings.CutPrefix(a, "--profile="); ok {
			profile = name
			continue
		}
		if a == "--profile" {
			if len(rest) == 0 {
				return "init: --profile needs a value\n" + initUsage(), 2
			}
			profile = rest[0]
			rest = rest[1:]
			continue
		}
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

	base, ok := denyProfiles[profile]
	if !ok {
		return fmt.Sprintf("init: unknown profile %q; expected one of %s\n%s", profile, strings.Join(profileNames(), ", "), initUsage()), 2
	}
	deny := append([]string(nil), base...)
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
	return prompts + fmt.Sprintf("init: wrote %s with %d deny entries (profile: %s). Review it, then run `cfgaudit %s` to verify.\n", path, len(deny), profile, dir), 0
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
		"  cfgaudit init [dir]              # write .claude/settings.json with a safe-default deny list\n" +
		"  cfgaudit init --profile <name>   # minimal | standard (default) | paranoid\n" +
		"  cfgaudit init --dry-run [dir]    # print the JSON without writing\n" +
		"  cfgaudit init --interactive      # show the baseline and add project-specific entries\n" +
		"  cfgaudit init --force [dir]      # overwrite an existing settings.json\n" +
		"\n" +
		"Profiles:\n" +
		"  minimal    credential reads only, the smallest list that still passes CFG006/CFG041-044\n" +
		"  standard   + destructive/network/privilege commands, further token stores, write\n" +
		"             protection on credential paths, and Edit(**/.claude/**)\n" +
		"  paranoid   + environment runners (npx, docker exec, devbox run, ...), shell\n" +
		"             interpreters, publish/infra commands, and the PowerShell equivalents\n"
}
