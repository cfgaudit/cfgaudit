package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// SkillsLock is a partial representation of a skills-lock.json file written by the
// vercel-labs/skills CLI (skills.sh) at a repo root. It declares the external
// sources the CLI pulls agent-skill (instruction) content from. Only the fields
// cfgaudit inspects are decoded; unknown top-level keys and schema versions are
// tolerated — the parser keys off the `skills` map, so a future schema bump does
// not break parsing.
type SkillsLock struct {
	Skills map[string]SkillEntry `json:"skills"`
}

// SkillEntry is one installed skill's source record. The skills CLI records the
// integrity of an installed skill in one of a few fields depending on its version;
// any of them pins the content so the upstream cannot silently change it:
//
//   - Source       — upstream slug ("owner/repo") or an on-disk path for local skills.
//   - SourceType   — "github" | "mintlify" | "huggingface" | "local" (may be absent).
//   - Ref          — branch, tag, or commit SHA requested (optional; a bare branch/tag is mutable).
//   - Commit       — the resolved commit SHA (40- or 64-hex; an immutable pin).
//   - ComputedHash — SHA-256 of the fetched skill content (the dominant v1-schema pin).
//   - Integrity    — SRI-style content hash ("sha256-…"; the commit/integrity schema variant).
//   - SkillPath    — subdirectory within the source (optional).
type SkillEntry struct {
	Source       string `json:"source"`
	SourceType   string `json:"sourceType"`
	Ref          string `json:"ref"`
	Commit       string `json:"commit"`
	ComputedHash string `json:"computedHash"`
	Integrity    string `json:"integrity"`
	SkillPath    string `json:"skillPath"`
}

// ParseSkillsLock reads and decodes a skills-lock.json file. A read error
// (including os.ErrNotExist) is returned unwrapped so callers can test it with
// errors.Is; a malformed body is reported as a parse error.
func ParseSkillsLock(path string) (*SkillsLock, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is resolved by the CLI from a user-supplied directory
	if err != nil {
		return nil, err
	}
	var sl SkillsLock
	if err := json.Unmarshal(data, &sl); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &sl, nil
}
