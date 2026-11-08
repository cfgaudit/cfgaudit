// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Gemini CLI and Qwen Code custom commands (#750). Both load every
// `**/*.toml` under .gemini/commands or .qwen/commands, and Qwen also every
// `**/*.md` (FileCommandLoader.ts, Gemini v0.67.0, Qwen v0.27.0). The text that
// reaches the model is the TOML `prompt` string, or the Markdown body after the
// frontmatter. Before it is sent, `@{path}` is replaced by the content of a
// file in the workspace and `!{cmd}` by the output of a shell command.

// CustomCommandTOML is a TOML custom command as both agents load it.
type CustomCommandTOML struct {
	// Prompt is the `prompt` string.
	Prompt string
	// Line is the 1-based line of the file where Prompt starts, 0 when it
	// cannot be found.
	Line int
}

// ParseCustomCommandTOML decodes a TOML custom command. ok is false when the
// agent would skip the file: TOML that does not parse, or a `prompt` that is
// missing or not a string (TomlCommandDefSchema). A UTF-8 byte-order mark is
// dropped first when stripBOM is set: Qwen Code strips it (stripUtf8Bom), and
// Gemini CLI hands it to @iarna/toml, whose parseStart rejects it as an
// unknown character.
func ParseCustomCommandTOML(data []byte, stripBOM bool) (CustomCommandTOML, bool) {
	text := string(data)
	if stripBOM {
		text = strings.TrimPrefix(text, "\ufeff")
	} else if strings.HasPrefix(text, "\ufeff") {
		return CustomCommandTOML{}, false
	}
	var doc map[string]any
	if _, err := toml.Decode(text, &doc); err != nil {
		return CustomCommandTOML{}, false
	}
	prompt, ok := doc["prompt"].(string)
	if !ok {
		return CustomCommandTOML{}, false
	}
	return CustomCommandTOML{Prompt: prompt, Line: tomlPromptLine(text)}, true
}

// tomlPromptKeyRe is a top-level `prompt =` assignment, the key bare or quoted.
var tomlPromptKeyRe = regexp.MustCompile(`^[ \t]*(?:prompt|"prompt"|'prompt')[ \t]*=[ \t]*(.*)$`)

// tomlPromptLine returns the line the prompt text starts on. A multi-line
// string that opens at the end of the key's line starts on the next line, as
// TOML drops a newline right after the opening delimiter. Only lines before the
// first table header are searched, since `prompt` must be a top-level key.
func tomlPromptLine(text string) int {
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(strings.TrimSpace(line), "[") {
			return 0
		}
		m := tomlPromptKeyRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		rest := strings.TrimSpace(m[1])
		if rest == `"""` || rest == `'''` {
			return i + 2
		}
		return i + 1
	}
	return 0
}

// customCommandFrontmatterRe is the frontmatter split of Qwen Code's
// parseMarkdownCommand (packages/core/src/utils/markdown-command.ts).
var customCommandFrontmatterRe = regexp.MustCompile(`^---\n(?:[\s\S]*?\n)?---(?:\n|$)`)

// CustomCommandMarkdownPrompt returns the prompt of a Qwen Code Markdown
// command. Qwen normalizes the text (BOM dropped, line endings to LF), cuts
// off a leading frontmatter block and trims the rest, so a `!{` inside the
// frontmatter does not run.
func CustomCommandMarkdownPrompt(content string) string {
	text := strings.TrimPrefix(content, "\ufeff")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	if loc := customCommandFrontmatterRe.FindStringIndex(text); loc != nil {
		text = text[loc[1]:]
	}
	return strings.TrimSpace(text)
}

// CustomCommandShellCommands returns the `!{...}` commands of a custom
// command prompt, in order, as both agents extract them (injectionParser.ts):
// the text after `!{` up to the brace that balances it, trimmed, with empty
// ones dropped. An unbalanced `!{` or `@{` makes the agent reject the whole
// command before any of it runs, so then there are none.
func CustomCommandShellCommands(prompt string) []string {
	if _, ok := customCommandInjections(prompt, "@{"); !ok {
		return nil
	}
	cmds, ok := customCommandInjections(prompt, "!{")
	if !ok {
		return nil
	}
	return cmds
}

// customCommandInjections is extractInjections: ok is false when an opening
// trigger has no balancing brace.
func customCommandInjections(prompt, trigger string) ([]string, bool) {
	var out []string
	index := 0
	for {
		start := strings.Index(prompt[index:], trigger)
		if start < 0 {
			return out, true
		}
		start += index
		depth := 1
		end := -1
		for i := start + len(trigger); i < len(prompt); i++ {
			switch prompt[i] {
			case '{':
				depth++
			case '}':
				depth--
			}
			if depth == 0 {
				end = i
				break
			}
		}
		if end < 0 {
			return nil, false
		}
		if cmd := strings.TrimSpace(prompt[start+len(trigger) : end]); cmd != "" {
			out = append(out, cmd)
		}
		index = end + 1
	}
}
