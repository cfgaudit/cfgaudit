// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/cfgaudit/cfgaudit/internal/finding"
)

type cfg142 struct{}

// CFG142 reports an MCP server, hook, task or `!` block that starts a
// container with docker run or podman run and a flag that hands the host to
// it: --privileged, a Docker socket mount, a kernel capability, a host
// namespace, an unconfined security profile, or a mount of the root, the
// home directory or a credential folder (#1682).
var CFG142 = &cfg142{}

func init() { All = append(All, CFG142) }

func (r *cfg142) ID() string { return "CFG142" }

// containerSite is one command that may start a container, as words.
type containerSite struct {
	label, file string
	words       []string
}

// containerEscape is one flag of a docker run that gives the container part
// of the host.
type containerEscape struct {
	flag, gives string
	sev         finding.Severity
}

func (r *cfg142) Check(t *Target) []finding.Finding {
	if t == nil {
		return nil
	}
	var findings []finding.Finding
	seen := map[string]bool{}
	for _, site := range containerSites(t) {
		escapes := containerEscapes(site.words)
		if len(escapes) == 0 {
			continue
		}
		sev := finding.Warn
		var parts []string
		for _, e := range escapes {
			if e.sev == finding.Error {
				sev = finding.Error
			}
			parts = append(parts, "\""+e.flag+"\" ("+e.gives+")")
		}
		msg := site.label + " starts a container with " + strings.Join(parts, ", ") +
			". The container runs on the machine of whoever opens the repository, and whatever the image or the server inside it does reaches the host through these flags. Remove them; mount only a folder inside the repository, and add a capability or a host namespace only for a container you build and review yourself" + userScopeNote(t)
		key := site.file + "\x00" + msg
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, finding.Finding{RuleID: "CFG142", Severity: sev, File: site.file, Message: msg})
	}
	return findings
}

// containerSites returns every committed command of t as words: the command
// sites (hooks, helpers, status lines, `!` blocks), every VS Code task and
// every MCP server launch. A Codex mcp_tool input is a value, not a command.
func containerSites(t *Target) []containerSite {
	var sites []containerSite
	for _, s := range commandSites(t) {
		if s.HookInput {
			continue
		}
		for _, seg := range splitCommands(s.Command) {
			sites = append(sites, containerSite{label: s.Label, file: s.File, words: shellWords(seg)})
		}
	}
	if tasks := t.VSCodeTasks; tasks != nil {
		for _, task := range tasks.Tasks {
			kind := "VS Code task"
			if task.RunOptions != nil && task.RunOptions.RunOn == "folderOpen" {
				kind = "VS Code folderOpen task"
			}
			for _, line := range task.CommandLines() {
				for _, seg := range splitCommands(line) {
					sites = append(sites, containerSite{label: kind + " \"" + task.Label + "\" command", file: t.VSCodeTasksFile, words: shellWords(seg)})
				}
			}
		}
	}
	for _, ref := range t.mcpServerRefs() {
		if ref.Server.Command == "" {
			continue
		}
		// The args are already words; a mount spec with a space stays one.
		words := append(shellWords(ref.Server.Command), ref.Server.Args...)
		sites = append(sites, containerSite{label: "mcpServers." + ref.Name + " command", file: ref.File, words: words})
	}
	return sites
}

// containerRunArgs returns the options of a docker run, docker container run,
// docker create or podman run in words, up to the image. nil when words start
// no container.
func containerRunArgs(words []string) []string {
	for i, w := range words {
		name := executableName(w)
		if name != "docker" && name != "podman" {
			continue
		}
		j := i + 1
		// Global options before the subcommand: docker --context x run.
		for j < len(words) && strings.HasPrefix(words[j], "-") {
			if dockerGlobalValueFlags[words[j]] {
				j++
			}
			j++
		}
		if j < len(words) && words[j] == "container" {
			j++
		}
		if j >= len(words) || (words[j] != "run" && words[j] != "create") {
			continue
		}
		var opts []string
		for k := j + 1; k < len(words); k++ {
			w := words[k]
			if !strings.HasPrefix(w, "-") || w == "-" {
				break // the image
			}
			if w == "--" {
				break
			}
			opts = append(opts, w)
			if !strings.Contains(w, "=") && runValueFlag(w) && k+1 < len(words) {
				k++
				opts = append(opts, words[k])
			}
		}
		return opts
	}
	return nil
}

// dockerGlobalValueFlags are the options before the subcommand that take a value.
var dockerGlobalValueFlags = map[string]bool{"--context": true, "-c": true, "--host": true, "-H": true, "--config": true, "--log-level": true, "-l": true}

// runValueLongFlags are the docker run options that take a value as the next
// word. A flag not listed is read as a switch, so an unknown option can only
// end the scan early, never turn the image into a flag.
var runValueLongFlags = map[string]bool{
	"--add-host": true, "--annotation": true, "--attach": true, "--blkio-weight": true, "--cap-add": true, "--cap-drop": true,
	"--cgroup-parent": true, "--cgroupns": true, "--cidfile": true, "--cpu-period": true, "--cpu-quota": true, "--cpu-shares": true,
	"--cpus": true, "--cpuset-cpus": true, "--cpuset-mems": true, "--device": true, "--device-cgroup-rule": true, "--dns": true,
	"--dns-option": true, "--dns-search": true, "--domainname": true, "--entrypoint": true, "--env": true, "--env-file": true,
	"--expose": true, "--gpus": true, "--group-add": true, "--health-cmd": true, "--health-interval": true, "--health-retries": true,
	"--health-start-period": true, "--health-timeout": true, "--hostname": true, "--ip": true, "--ip6": true, "--ipc": true,
	"--isolation": true, "--kernel-memory": true, "--label": true, "--label-file": true, "--link": true, "--log-driver": true,
	"--log-opt": true, "--mac-address": true, "--memory": true, "--memory-reservation": true, "--memory-swap": true,
	"--mount": true, "--name": true, "--net": true, "--network": true, "--network-alias": true, "--pid": true, "--pids-limit": true,
	"--platform": true, "--publish": true, "--pull": true, "--restart": true, "--runtime": true, "--security-opt": true,
	"--shm-size": true, "--stop-signal": true, "--stop-timeout": true, "--storage-opt": true, "--sysctl": true, "--tmpfs": true,
	"--ulimit": true, "--user": true, "--userns": true, "--uts": true, "--volume": true, "--volumes-from": true, "--workdir": true,
}

func runValueFlag(w string) bool {
	if strings.HasPrefix(w, "--") {
		return runValueLongFlags[w]
	}
	// A short option takes a value when its last letter does: -v, -e, -p,
	// -w, -u, -l, -h, -m, -a, and the bundle -itv.
	return len(w) >= 2 && strings.ContainsRune("vepwulhma", rune(w[len(w)-1]))
}

// containerEscapes returns the flags of the container started in words that
// give it part of the host.
func containerEscapes(words []string) []containerEscape {
	opts := containerRunArgs(words)
	var out []containerEscape
	for i := 0; i < len(opts); i++ {
		name, value := opts[i], ""
		if eq := strings.IndexByte(name, '='); eq > 0 && strings.HasPrefix(name, "--") {
			name, value = name[:eq], name[eq+1:]
		} else if runValueFlag(name) && i+1 < len(opts) {
			value = opts[i+1]
			i++
		}
		shown := name
		if value != "" {
			shown = name + " " + value
		}
		switch {
		case name == "--privileged":
			if value == "" || strings.EqualFold(value, "true") {
				out = append(out, containerEscape{shown, "every device and capability of the host, the classic container escape", finding.Error})
			}
		case name == "-v" || name == "--volume" || (strings.HasPrefix(name, "-") && !strings.HasPrefix(name, "--") && strings.HasSuffix(name, "v")):
			if gives, sev := hostMount(volumeSource(value)); gives != "" {
				out = append(out, containerEscape{shown, gives, sev})
			}
		case name == "--mount":
			if gives, sev := hostMount(mountSource(value)); gives != "" {
				out = append(out, containerEscape{shown, gives, sev})
			}
		case name == "--cap-add":
			if gives, sev := addedCapability(value); gives != "" {
				out = append(out, containerEscape{shown, gives, sev})
			}
		case name == "--pid" && strings.EqualFold(value, "host"):
			out = append(out, containerEscape{shown, "every process of the host, to read and signal", finding.Error})
		case (name == "--network" || name == "--net") && strings.EqualFold(value, "host"):
			out = append(out, containerEscape{shown, "the host's network, including services bound to localhost", finding.Warn})
		case (name == "--ipc" || name == "--uts" || name == "--userns" || name == "--cgroupns") && strings.EqualFold(value, "host"):
			out = append(out, containerEscape{shown, "a namespace of the host", finding.Warn})
		case name == "--security-opt" && unconfinedOptRe.MatchString(value):
			out = append(out, containerEscape{shown, "no syscall filter or mandatory access control", finding.Warn})
		}
	}
	return out
}

// unconfinedOptRe is a --security-opt that drops a protection.
var unconfinedOptRe = regexp.MustCompile(`(?i)^(?:seccomp|apparmor|systempaths)[=:]unconfined$|^label[=:]disable$`)

// volumeSource is the host side of a -v spec: /a:/b:ro gives /a. A Windows
// drive letter (C:\x:/y) is kept. A named volume has no slash and is returned
// as is, which hostMount ignores.
func volumeSource(spec string) string {
	if len(spec) > 2 && isASCIILetter(spec[0]) && spec[1] == ':' && (spec[2] == '\\' || spec[2] == '/') {
		if i := strings.IndexByte(spec[2:], ':'); i >= 0 {
			return spec[:2+i]
		}
		return spec
	}
	if i := strings.IndexByte(spec, ':'); i >= 0 {
		return spec[:i]
	}
	return ""
}

// mountSource is the source of a --mount type=bind,source=/a,target=/b.
func mountSource(spec string) string {
	for _, kv := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if ok && (k == "source" || k == "src") {
			return v
		}
	}
	return ""
}

// homeRe is the home directory of the reader, written any way a command or a
// committed file can: ~, $HOME, ${HOME}, %USERPROFILE%, ${env:HOME},
// ${userHome}, /home/<user>, /Users/<user>, C:\Users\<user>.
var homeRe = regexp.MustCompile(`(?i)^(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE|\$\{env:(?:HOME|USERPROFILE)\}|\$\{userHome\}|/home/[^/]+|/Users/[^/]+|[A-Z]:[\\/]Users[\\/][^\\/]+)$`)

// credentialDirs are the folders under the home directory that hold keys,
// tokens or cloud credentials.
var credentialDirs = map[string]bool{
	".ssh": true, ".aws": true, ".azure": true, ".kube": true, ".docker": true, ".gnupg": true,
	".config": true, ".config/gcloud": true, ".config/gh": true, ".npmrc": true, ".netrc": true,
	".git-credentials": true, ".pypirc": true, ".claude": true, ".codex": true, ".gemini": true,
}

// dockerSocketRe is the Docker or Podman API socket, or its Windows pipe.
var dockerSocketRe = regexp.MustCompile(`(?i)(?:^|/)(?:docker|podman)\.sock$|^\\\\\.\\pipe\\docker_engine$|^//\./pipe/docker_engine$`)

// hostMount says what a bind mount of src gives the container, and how bad
// that is; "" for a folder inside the repository, a named volume or anything
// else.
func hostMount(src string) (string, finding.Severity) {
	src = strings.Trim(src, `"'`)
	if src == "" {
		return "", ""
	}
	if dockerSocketRe.MatchString(src) {
		return "the host's container daemon, which is root on the host", finding.Error
	}
	clean := strings.TrimRight(strings.ReplaceAll(src, `\`, "/"), "/")
	switch strings.ToLower(clean) {
	case "", "/.", "/*":
		return "the host's whole file system", finding.Error
	case "/etc", "/root":
		return "the host's system configuration or root's home", finding.Error
	case "/proc", "/sys", "/dev", "/boot", "/var/run", "/run":
		return "a kernel or system folder of the host", finding.Warn
	}
	if len(clean) == 2 && isASCIILetter(clean[0]) && clean[1] == ':' {
		return "the host's whole drive", finding.Error
	}
	if homeRe.MatchString(clean) {
		return "the home directory of whoever opens the repository", finding.Error
	}
	for i := 1; i < len(clean); i++ {
		if clean[i] != '/' || !homeRe.MatchString(clean[:i]) {
			continue
		}
		if credentialPath(clean[i+1:]) {
			return "the credentials in ~/" + clean[i+1:] + " of whoever opens the repository", finding.Error
		}
		return "", ""
	}
	return "", ""
}

// credentialPath reports whether rest, a path below the home directory, is a
// credential folder or lies in one. ~/.config counts only as a whole or for
// the folders listed, since most of it is plain application settings.
func credentialPath(rest string) bool {
	if credentialDirs[rest] {
		return true
	}
	for dir := range credentialDirs {
		if dir != ".config" && strings.HasPrefix(rest, dir+"/") {
			return true
		}
	}
	return false
}

// addedCapability says what --cap-add gives: ALL and SYS_ADMIN are an escape,
// the curated others a kernel power. Capabilities Docker grants by default
// (NET_BIND_SERVICE, CHOWN, …) and harmless ones are not reported.
func addedCapability(v string) (string, finding.Severity) {
	c := strings.TrimPrefix(strings.ToUpper(strings.Trim(v, `"'`)), "CAP_")
	switch c {
	case "ALL":
		return "every kernel capability", finding.Error
	case "SYS_ADMIN":
		return "mount and most other kernel operations, enough to escape", finding.Error
	case "SYS_PTRACE":
		return "reading and writing the memory of other processes", finding.Warn
	case "SYS_MODULE":
		return "loading kernel modules", finding.Warn
	case "NET_ADMIN":
		return "reconfiguring the network and firewall", finding.Warn
	case "SYS_RAWIO", "DAC_READ_SEARCH", "BPF":
		return "a kernel power that reaches past the container", finding.Warn
	}
	return "", ""
}

func isASCIILetter(c byte) bool {
	return 'a' <= c|0x20 && c|0x20 <= 'z'
}
