package rules

import (
	"sort"
	"strings"
)

// instructionSource is one block of agent-instruction text in scope for the
// content rules (CFG024/026/029–036/057). It is either the loaded instruction
// file (CLAUDE.md, .cursorrules, AGENTS.md, …) or a type:"prompt" hook, whose
// text Claude Code injects into its own context when the hook event fires.
// Because a prompt-hook is read as trusted guidance just like an instruction
// file, it is the same prompt-injection surface and the content rules must scan
// it too (#235) — the instruction analogue of commandSites for the command rules.
type instructionSource struct {
	// File is the config file the text was declared in, so a finding is
	// attributed correctly (CLAUDE.md vs the settings/hooks.json carrying a hook).
	File string
	// Name is the finding-friendly origin used in messages — the instruction
	// file's base name, or "hooks.<event> prompt" for a prompt-hook.
	Name string
	// Content is the text to scan. For a prompt-hook this is the injected prompt;
	// line numbers a rule reports are relative to this text.
	Content string
}

// instructionSources returns every block of instruction text to scan: the
// loaded instruction file first (when present), then each type:"prompt" hook in
// settings, in stable event order. A target with a single instruction file and
// no prompt-hooks yields exactly that one source, so the content rules behave
// identically to before. Frontmatter-based rules (CFG051/056) read Frontmatter
// directly and do not use this. Returns nil for a nil target.
func (t *Target) instructionSources() []instructionSource {
	if t == nil {
		return nil
	}
	var srcs []instructionSource
	if t.InstructionContent != "" {
		srcs = append(srcs, instructionSource{
			File:    t.InstructionFile,
			Name:    t.instructionName(),
			Content: t.InstructionContent,
		})
	}
	srcs = append(srcs, t.promptHookSources()...)
	srcs = append(srcs, t.continueRuleSources()...)
	return srcs
}

// continueRuleSources returns one instructionSource per Continue rule and prompt
// — trusted instruction context loaded by Continue, the same prompt-injection
// surface as a CLAUDE.md — attributed to the Continue config file.
func (t *Target) continueRuleSources() []instructionSource {
	if t == nil || t.Continue == nil {
		return nil
	}
	var srcs []instructionSource
	label := func(kind, name string) string {
		if name = strings.TrimSpace(name); name != "" {
			return "Continue " + kind + " \"" + name + "\""
		}
		return "Continue " + kind
	}
	for _, r := range t.Continue.Rules {
		if strings.TrimSpace(r.Text) != "" {
			srcs = append(srcs, instructionSource{File: t.ContinueFile, Name: label("rule", r.Name), Content: r.Text})
		}
	}
	for _, p := range t.Continue.Prompts {
		if strings.TrimSpace(p.Prompt) != "" {
			srcs = append(srcs, instructionSource{File: t.ContinueFile, Name: label("prompt", p.Name), Content: p.Prompt})
		}
	}
	return srcs
}

// promptHookSources returns one instructionSource per prompt-bearing hook in the
// target's settings, attributed to the settings/hooks.json file and labelled by
// event, in sorted event order. It covers both hook types that inject a prompt
// into Claude's context: type:"prompt" (LLM prompt hooks) and type:"agent"
// (multi-turn verification hooks) — both carry a `prompt` field of trusted text.
func (t *Target) promptHookSources() []instructionSource {
	if t == nil || t.Settings == nil {
		return nil
	}
	events := make([]string, 0, len(t.Settings.Hooks))
	for e := range t.Settings.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)

	var srcs []instructionSource
	for _, event := range events {
		for _, group := range t.Settings.Hooks[event] {
			for _, h := range group.Hooks {
				if (h.Type == "prompt" || h.Type == "agent") && h.Prompt != "" {
					label := "hooks." + event + " prompt"
					if h.Type == "agent" {
						label = "hooks." + event + " agent prompt"
					}
					srcs = append(srcs, instructionSource{
						File:    t.SettingsFile,
						Name:    label,
						Content: h.Prompt,
					})
				}
			}
		}
	}
	return srcs
}
