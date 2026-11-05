// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"github.com/cfgaudit/cfgaudit/internal/safeyaml"
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
	// Rules restricts a structured source to the content rules that are
	// semantically valid for it. Nil means every instruction-content rule.
	Rules map[string]bool
}

// instructionSources returns every block of instruction text to scan: the
// loaded instruction file first (when present), then each type:"prompt" hook in
// settings, in stable event order. A target with a single instruction file and
// no prompt-hooks yields exactly that one source, so the content rules behave
// identically to before. Frontmatter-based rules (CFG051/056) read Frontmatter
// directly and do not use this. Returns nil for a nil target.
func (t *Target) instructionSources() []instructionSource {
	return t.instructionSourcesFor("")
}

func (t *Target) instructionSourcesFor(ruleID string) []instructionSource {
	if t == nil {
		return nil
	}
	var srcs []instructionSource
	// Gemini ignores a remote agent file's Markdown body. For an inline card,
	// the raw serialized JSON is also not a second model-visible representation;
	// its selected fields are registered below with their JSON paths instead.
	if t.InstructionContent != "" && (t.GeminiRemote == nil || !t.GeminiRemote.HasInlineCard) {
		srcs = append(srcs, instructionSource{
			File:    t.InstructionFile,
			Name:    t.instructionName(),
			Content: t.InstructionContent,
		})
	}
	srcs = append(srcs, t.promptHookSources()...)
	srcs = append(srcs, t.continueRuleSources()...)
	srcs = append(srcs, t.continueHookPromptSources()...)
	srcs = append(srcs, t.openCodePromptSources()...)
	srcs = append(srcs, t.copilotPromptOverrideSources()...)
	srcs = append(srcs, t.geminiAgentCardSources()...)
	if ruleID == "" {
		return srcs
	}
	filtered := srcs[:0]
	for _, src := range srcs {
		if src.Rules == nil || src.Rules[ruleID] {
			filtered = append(filtered, src)
		}
	}
	return filtered
}

var geminiAgentCardContentRules = map[string]bool{
	"CFG026": true, "CFG030": true, "CFG031": true, "CFG032": true,
	"CFG033": true, "CFG036": true, "CFG080": true, "CFG113": true,
	"CFG120": true,
}

// geminiAgentCardSources returns exactly the fields Gemini CLI copies into the
// remote-agent tool description: the frontmatter description, card description,
// and each skill name/description. Other valid Agent Card fields are opaque to
// the model in agentRegistry.registerRemoteAgent and are deliberately omitted.
func (t *Target) geminiAgentCardSources() []instructionSource {
	remote := t.GeminiRemote
	if remote == nil || !remote.HasInlineCard {
		return nil
	}
	prefix := strings.Repeat("\n", max(remote.CardLine-1, 0))
	seen := map[string]bool{}
	var srcs []instructionSource
	add := func(name, content string) {
		content = strings.TrimSpace(content)
		if content == "" || seen[content] {
			return
		}
		seen[content] = true
		srcs = append(srcs, instructionSource{
			File: t.InstructionFile, Name: name,
			Content: prefix + content, Rules: geminiAgentCardContentRules,
		})
	}
	for _, field := range remote.InlineCardText {
		if field.Path == "$.description" ||
			(strings.HasPrefix(field.Path, "$.skills[") &&
				(strings.HasSuffix(field.Path, "].name") || strings.HasSuffix(field.Path, "].description"))) {
			add("agent_card_json "+field.Path, field.Text)
		}
	}
	add("Gemini remote agent frontmatter description", remote.UserDescription)
	return srcs
}

// copilotPromptOverrideKey is the Copilot Chat setting whose inline YAML replaces
// the system prompt and tool descriptions of every agent request (#648).
const copilotPromptOverrideKey = "github.copilot.chat.debug.promptOverrideString"

// copilotPromptOverrideSources returns the systemPrompt and tool descriptions of
// an inline Copilot prompt override in .vscode/settings.json. toolCallingLoop.ts
// applies them in place of the built prompt and tool list
// (applyConfiguredPromptOverrides), so they are instruction text on the same
// footing as an instruction file, read by whoever committed the settings file.
func (t *Target) copilotPromptOverrideSources() []instructionSource {
	if t == nil || t.VSCodeSettings == nil {
		return nil
	}
	text, ok := t.VSCodeSettings.StringField(copilotPromptOverrideKey)
	if !ok || strings.TrimSpace(text) == "" {
		return nil
	}
	var doc struct {
		SystemPrompt     string `yaml:"systemPrompt"`
		ToolDescriptions map[string]struct {
			Description string `yaml:"description"`
		} `yaml:"toolDescriptions"`
	}
	if safeyaml.Unmarshal([]byte(text), &doc) != nil {
		return nil
	}
	var srcs []instructionSource
	if strings.TrimSpace(doc.SystemPrompt) != "" {
		srcs = append(srcs, instructionSource{File: t.VSCodeSettingsFile, Name: copilotPromptOverrideKey + " systemPrompt", Content: doc.SystemPrompt})
	}
	for _, name := range sortedToolDescKeys(doc.ToolDescriptions) {
		if d := doc.ToolDescriptions[name].Description; strings.TrimSpace(d) != "" {
			srcs = append(srcs, instructionSource{File: t.VSCodeSettingsFile, Name: copilotPromptOverrideKey + " toolDescriptions." + name, Content: d})
		}
	}
	return srcs
}

func sortedToolDescKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// openCodePromptSources returns the instruction text an opencode.json carries
// inline: an agent's `prompt`, which replaces that agent's instructions, and a
// command's `template`, which is the text the command sends. Both are trusted
// context written by whoever committed the file, so they are the same
// prompt-injection surface as an instruction file.
//
// `instructions` is deliberately not here: it names additional files and glob
// patterns rather than carrying text, so covering it means resolving those paths
// and reading them, which is discovery work rather than another source.
func (t *Target) openCodePromptSources() []instructionSource {
	if t == nil || t.OpenCode == nil {
		return nil
	}
	var srcs []instructionSource
	for _, name := range sortedKeys2(t.OpenCode.Agent) {
		if text := strings.TrimSpace(t.OpenCode.Agent[name].Prompt); text != "" {
			srcs = append(srcs, instructionSource{
				File:    t.OpenCodeFile,
				Name:    "opencode agent \"" + name + "\" prompt",
				Content: t.OpenCode.Agent[name].Prompt,
			})
		}
	}
	for _, name := range sortedKeys2(t.OpenCode.Command) {
		if text := strings.TrimSpace(t.OpenCode.Command[name].Template); text != "" {
			srcs = append(srcs, instructionSource{
				File:    t.OpenCodeFile,
				Name:    "opencode command \"" + name + "\" template",
				Content: t.OpenCode.Command[name].Template,
			})
		}
	}
	return srcs
}

// continueHookPromptSources returns one instructionSource per prompt-bearing
// handler in a Continue settings file's hooks block. Continue's "prompt" and
// "agent" handler types both carry a `prompt` field that is sent to a model when
// the event fires, so a committed one is trusted text the content rules must
// scan — the same reasoning as promptHookSources for settings.json.
func (t *Target) continueHookPromptSources() []instructionSource {
	ch := t.ContinueHooks
	if ch == nil || ch.DisableAllHooks || len(ch.Hooks) == 0 {
		return nil
	}
	var srcs []instructionSource
	for _, event := range sortedKeys2(ch.Hooks) {
		for _, group := range ch.Hooks[event] {
			for _, h := range group.Hooks {
				if (h.Type == "prompt" || h.Type == "agent") && h.Prompt != "" {
					label := "Continue hooks." + event + " prompt"
					if h.Type == "agent" {
						label = "Continue hooks." + event + " agent prompt"
					}
					srcs = append(srcs, instructionSource{File: t.ContinueHooksFile, Name: label, Content: h.Prompt})
				}
			}
		}
	}
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
