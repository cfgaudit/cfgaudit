// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

// Package benchcorpus generates the synthetic inputs the benchmarks scan
// (#1016). Everything is built from a fixed seed, so two commits that scan the
// same corpus can be compared, and nothing is copied from a real repository.
//
// The text is neutral project documentation. Ordinary words such as "you",
// "when", "before", "config" or "list" are literals of the content rules'
// prefilter (rules/prefilter.go), so a share of the lines passes the prefilter
// and reaches the regexp without matching it. That is the expensive path of a
// real scan, and the reason the corpus is prose rather than filler.
//
// Changing what this package writes changes every benchmark number. Do it in a
// commit of its own, so the benchmark history shows where the baseline moved.
package benchcorpus

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
)

// Profile sizes a generated project tree.
type Profile struct {
	// Seed tells the profiles' text apart; it is fixed like the rest.
	Seed                                              uint64
	Skills, Commands, Agents, CursorRules, ClineRules int
	// Lines is the length of each instruction file, frontmatter included.
	Lines int
}

var (
	// Repo is sized like a large open-source agent repository: about 37
	// targets and 4,000 instruction lines.
	Repo = Profile{Seed: 1, Skills: 12, Commands: 8, Agents: 4, CursorRules: 4, ClineRules: 4, Lines: 110}
	// Large is sized like a developer's --user scan with plugins and skills:
	// about 118 targets and 13,000 instruction lines.
	Large = Profile{Seed: 2, Skills: 50, Commands: 30, Agents: 14, CursorRules: 10, ClineRules: 10, Lines: 110}
)

// seed is fixed: the corpus must not change between runs.
const seed = 1016

// newRand is deliberately math/rand: the corpus must be the same on every run,
// and nothing about it is secret.
func newRand(salt uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, salt)) //nolint:gosec // G404: reproducible test data, not a secret
}

var (
	subjects = []string{"The build", "The CLI", "Each package", "The parser", "The test suite", "The release job",
		"The config loader", "The docs site", "The formatter", "The cache", "The API client", "This module"}
	verbs = []string{"reads", "writes", "checks", "skips", "loads", "parses", "formats", "lists", "updates",
		"validates", "renders", "collects"}
	objects = []string{"the go.mod file", "every Markdown page", "the fixture tree", "the changelog",
		"the generated schema", "the session log", "the test data", "the config file", "the version string",
		"the module graph", "the output table", "the content of each section"}
	tails = []string{"before the tests run.", "when the flag is set.", "after a release.", "in CI only.",
		"for each platform.", "on every push.", "if the file exists.", "without network access.",
		"in a temporary directory.", "with the default settings.", "at startup.", "once per run."}
	// asides are sentences addressed to the reader, the register agent
	// instruction files use. Several contain prefilter literals.
	asides = []string{
		"You can run the whole suite with make test.",
		"When you add a package, list it in the README.",
		"Keep the data in testdata, not next to the code.",
		"Use the map in config.go to find the right loader.",
		"Ask for a review before you merge a large change.",
		"Prefer small commits that tell one story each.",
		"The session tokens in the examples are placeholders.",
		"Find the owner of a file in CODEOWNERS.",
		"Open the http docs at https://example.invalid/docs.",
		"A summary of each release is in CHANGELOG.md.",
	}
	commands = []string{"go test ./...", "go vet ./...", "make build", "make lint", "gofmt -l .",
		"go run ./cmd/tool --help", "git status --short", "go mod tidy"}
	headings = []string{"Overview", "Layout", "Build", "Tests", "Style", "Releases", "Docs", "Tooling"}
)

func sentence(r *rand.Rand) string {
	if r.IntN(4) == 0 {
		return asides[r.IntN(len(asides))]
	}
	return fmt.Sprintf("%s %s %s %s", subjects[r.IntN(len(subjects))], verbs[r.IntN(len(verbs))],
		objects[r.IntN(len(objects))], tails[r.IntN(len(tails))])
}

// Instruction returns an instruction file of about the given number of lines,
// the same text on every call.
func Instruction(lines int) string { return body(newRand(0), lines) }

// body returns lines of Markdown: headings, paragraphs, bullet lists and
// fenced shell blocks, in proportions typical of a project instruction file.
func body(r *rand.Rand, lines int) string {
	var b strings.Builder
	for n := 0; n < lines; {
		switch k := r.IntN(10); {
		case k == 0:
			fmt.Fprintf(&b, "## %s\n\n", headings[r.IntN(len(headings))])
			n += 2
		case k <= 2:
			b.WriteString("```sh\n")
			c := 1 + r.IntN(3)
			for i := 0; i < c; i++ {
				b.WriteString(commands[r.IntN(len(commands))] + "\n")
			}
			b.WriteString("```\n\n")
			n += c + 3
		case k <= 5:
			c := 2 + r.IntN(4)
			for i := 0; i < c; i++ {
				b.WriteString("- " + sentence(r) + "\n")
			}
			b.WriteString("\n")
			n += c + 1
		default:
			c := 1 + r.IntN(3)
			for i := 0; i < c; i++ {
				if i > 0 {
					b.WriteString(" ")
				}
				b.WriteString(sentence(r))
			}
			b.WriteString("\n\n")
			n += 2
		}
	}
	return b.String()
}

func skill(r *rand.Rand, name string, lines int) string {
	return fmt.Sprintf("---\nname: %s\ndescription: Formats and checks the %s output of the project.\n---\n\n# %s\n\n%s",
		name, name, name, body(r, lines-6))
}

// settings is a project .claude/settings.json with a permission block and a
// few hooks, all of them harmless, so the settings rules have work to do.
const settings = `{
  "permissions": {
    "allow": ["Bash(go test:*)", "Bash(go vet:*)", "Bash(make build)", "Read(./docs/**)"],
    "deny": ["Read(./.env)", "Read(~/.ssh/**)", "Bash(rm -rf /)"]
  },
  "hooks": {
    "PostToolUse": [
      {"matcher": "Edit|Write", "hooks": [{"type": "command", "command": "gofmt -l ."}]}
    ],
    "Stop": [
      {"hooks": [{"type": "command", "command": "go vet ./..."}]}
    ]
  }
}
`

const mcp = `{
  "mcpServers": {
    "docs": {"command": "/usr/local/bin/docs-server", "args": ["--root", "./docs"]},
    "tickets": {"type": "http", "url": "https://example.invalid/mcp"}
  }
}
`

// Write builds a project tree for p under dir.
func Write(dir string, p Profile) error {
	r := newRand(p.Seed)
	files := map[string]string{
		"CLAUDE.md":                       "# Project\n\n" + body(r, p.Lines),
		"AGENTS.md":                       "# Agents\n\n" + body(r, p.Lines),
		".github/copilot-instructions.md": body(r, p.Lines),
		".claude/settings.json":           settings,
		".mcp.json":                       mcp,
	}
	for i := 0; i < p.Skills; i++ {
		name := fmt.Sprintf("skill-%02d", i)
		files[filepath.Join(".claude", "skills", name, "SKILL.md")] = skill(r, name, p.Lines)
	}
	for i := 0; i < p.Commands; i++ {
		files[filepath.Join(".claude", "commands", fmt.Sprintf("cmd-%02d.md", i))] =
			"---\ndescription: Runs a project task.\n---\n\n" + body(r, p.Lines-4)
	}
	for i := 0; i < p.Agents; i++ {
		name := fmt.Sprintf("agent-%02d", i)
		files[filepath.Join(".claude", "agents", name+".md")] =
			"---\nname: " + name + "\ndescription: Reviews changes.\ntools: Read, Grep\n---\n\n" + body(r, p.Lines-6)
	}
	for i := 0; i < p.CursorRules; i++ {
		files[filepath.Join(".cursor", "rules", fmt.Sprintf("rule-%02d.mdc", i))] =
			"---\ndescription: Project style.\nglobs: \"**/*.go\"\n---\n\n" + body(r, p.Lines-5)
	}
	for i := 0; i < p.ClineRules; i++ {
		files[filepath.Join(".clinerules", fmt.Sprintf("rule-%02d.md", i))] = body(r, p.Lines)
	}
	for rel, content := range files {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// LongLine is a single paragraph of about n bytes with no line break.
func LongLine(n int) string {
	r := newRand(3)
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(sentence(r) + " ")
	}
	return b.String()
}

// DenseLine is a line of about n bytes made of prefilter literals that never
// form a match, so every filtered regexp runs over the whole line.
func DenseLine(n int) string {
	words := []string{"you", "when", "before", "content", "data", "list", "find", "map", "allow", "trust",
		"session", "config", "server", "tool", "approve", "http", "time", "after", "show", "input"}
	r := newRand(4)
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(words[r.IntN(len(words))] + " and ")
	}
	return b.String()
}

// LargeSettings is a settings.json with n allow and n deny entries.
func LargeSettings(n int) string {
	var allow, deny []string
	for i := 0; i < n; i++ {
		allow = append(allow, fmt.Sprintf(`"Bash(make target-%d)"`, i))
		deny = append(deny, fmt.Sprintf(`"Read(./secret-%d/**)"`, i))
	}
	return `{"permissions":{"allow":[` + strings.Join(allow, ",") + `],"deny":[` + strings.Join(deny, ",") + `]}}`
}
