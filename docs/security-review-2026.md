# Security review (2026)

## Review record

- **Reviewer:** repository security review
- **Date:** 2026-10-21
- **Commit:** [`591a4471bdef53d5e5d2905c3ebdc536a51bce4c`](https://github.com/cfgaudit/cfgaudit/commit/591a4471bdef53d5e5d2905c3ebdc536a51bce4c)
- **Scope:** the Go scanner, its parsers and output encoders, `bin/cfgaudit`, and the release/build workflows at that commit.
- **Tracking:** [issue #759](https://github.com/cfgaudit/cfgaudit/issues/759)

This is a bounded review of the checked-out commit, not a claim that cfgaudit detects every unsafe agent configuration. The review used repository evidence and the hosted checks recorded below. No private vulnerability report was created; any exploitable vulnerability found in future must follow [SECURITY.md](../SECURITY.md#reporting-a-vulnerability), rather than a public issue.

## Security boundary

The reviewed boundary is the one in [SECURITY.md](../SECURITY.md#trust-boundary): repository content is hostile. Command-line flags and the paths explicitly supplied through `--config`, `--plugins`, and `--user` are trusted inputs. The scanner may read repository files, but must not execute them, read outside the scan root, disclose their contents in reports, or fail open on crafted input. The plugin wrapper is a separate boundary: it may download a release binary, but must verify the downloaded archive before executing it.

## Method and evidence

The review walked each entry in the [attack surface](design.md#attack-surface) through the implementation:

- Discovery and parsing call [`internal/scanroot`](https://github.com/cfgaudit/cfgaudit/tree/591a4471bdef53d5e5d2905c3ebdc536a51bce4c/internal/scanroot) for repository reads. The direct `os.ReadFile` calls are limited to user-supplied `--config` and files written by the trusted `init`/`policy` commands; the process-start sites are [`internal/version/version.go`](https://github.com/cfgaudit/cfgaudit/blob/591a4471bdef53d5e5d2905c3ebdc536a51bce4c/internal/version/version.go) and [`rules/cfg045.go`](https://github.com/cfgaudit/cfgaudit/blob/591a4471bdef53d5e5d2905c3ebdc536a51bce4c/rules/cfg045.go).
- `claude --version` uses fixed arguments and only parses its output as a version. `shellcheck` uses fixed arguments and receives command text on stdin; neither path invokes a shell for repository content.
- Findings and encoders were reviewed for value quoting. Rule messages use keys, labels, paths, and static diagnostics; the documented exception is CFG109, whose parser error may quote a small fragment of an already-committed malformed file.
- [`bin/cfgaudit`](https://github.com/cfgaudit/cfgaudit/blob/591a4471bdef53d5e5d2905c3ebdc536a51bce4c/bin/cfgaudit) was reviewed from PATH lookup through download, checksum selection, extraction, cache placement, and `exec`.
- [`release.yml`](https://github.com/cfgaudit/cfgaudit/blob/591a4471bdef53d5e5d2905c3ebdc536a51bce4c/.github/workflows/release.yml), [`docker.yml`](https://github.com/cfgaudit/cfgaudit/blob/591a4471bdef53d5e5d2905c3ebdc536a51bce4c/.github/workflows/docker.yml), and their reusable build workflows were checked for exact-SHA CI gating, least-privilege permissions, pinned actions, egress restrictions, signing, provenance, and SBOM publication.
- Native fuzz targets cover path parsers, Markdown instruction parsing, terminal-base parsing, JSONC stripping, and full scans including output encoders: [`internal/parser/fuzz_test.go`](https://github.com/cfgaudit/cfgaudit/blob/591a4471bdef53d5e5d2905c3ebdc536a51bce4c/internal/parser/fuzz_test.go) and [`cmd/cfgaudit/fuzz_test.go`](https://github.com/cfgaudit/cfgaudit/blob/591a4471bdef53d5e5d2905c3ebdc536a51bce4c/cmd/cfgaudit/fuzz_test.go).

## Check results

The following results are tied to the reviewed commit, not inferred from a different revision:

| Check | Result | Evidence |
|---|---|---|
| Go build, tests, race tests, cross-platform tests, coverage, govulncheck, lint/gosec, zizmor, Docker/security jobs, and action smoke test | Passed | [CI run 39511506491](https://github.com/cfgaudit/cfgaudit/actions/runs/39511506491) for `591a4471bdef53d5e5d2905c3ebdc536a51bce4c` |
| Native fuzzers | Passed | [Fuzz run 39511506457](https://github.com/cfgaudit/cfgaudit/actions/runs/39511506457) for the reviewed SHA |
| CodeQL | Passed | [CodeQL run 39511506390](https://github.com/cfgaudit/cfgaudit/actions/runs/39511506390) |
| OpenSSF Scorecard | Passed | [Scorecard run 39511506120](https://github.com/cfgaudit/cfgaudit/actions/runs/39511506120) |
| Local Go test/build and local gosec, govulncheck, and zizmor reruns | Unavailable | Go and these tools are not installed in the review environment; no local result is claimed |
| Local Markdown link checker | Unavailable | `lychee` is not installed; hosted link checking remains the authoritative check |

## Findings

### F-1: checksum verification is optional when no hash utility exists

- **Severity:** Low hardening gap
- **Status:** Tracked by [#759](https://github.com/cfgaudit/cfgaudit/issues/759) as a review observation; no public vulnerability advisory was opened
- **Evidence:** [`bin/cfgaudit` lines 83-94](https://github.com/cfgaudit/cfgaudit/blob/591a4471bdef53d5e5d2905c3ebdc536a51bce4c/bin/cfgaudit#L83-L94) sets `got` to empty when neither `sha256sum` nor `shasum` exists, then does not reject the archive.
- **Impact:** On an unusual host with neither utility, the wrapper can execute a downloaded archive without comparing it to `checksums.txt`. The normal Linux and macOS environments supported by the wrapper provide one of these utilities, and the archive and checksum are still fetched over HTTPS, so this was not assessed as an exploitable vulnerability in the bounded review. It does, however, weaken the assurance-case claim that the wrapper verifies every download.
- **Disposition:** Follow-up should make the no-hasher path fail closed or use a bundled/portable verifier. If an exploit path is demonstrated, report it privately under [SECURITY.md](../SECURITY.md#reporting-a-vulnerability).

No other security findings were identified in this bounded review. In particular, repository reads were mediated by `scanroot`, the two subprocesses did not execute scanned command text, output review found no intentional quoting of secret values or outside-file contents, and the release workflows had the stated CI, egress, permission, signing, and provenance controls.

## Assurance-case result

| Claim from [`docs/design.md`](design.md#assurance-case) | Result | Basis and limitation |
|---|---|---|
| Scanning hostile repository content does not execute it | Holds for reviewed code | Fixed-argument `claude --version`; stdin-only `shellcheck`; rules parse and match text. A compromised trusted PATH binary remains outside this boundary. |
| Scanning does not read or disclose files outside the scan directory | Holds for repository reads | `scanroot.ReadFile`/`Open` resolve and reject escapes; explicit trusted paths are intentionally exempt. CFG109 may quote malformed content already in the repository. |
| Repository content cannot change the result without the user seeing it | Holds with documented trust limitation | A repository `.cfgaudit.yml` is announced and can disable rules; untrusted CI must provide its own `--config`. False negatives remain possible because this is a static linter. |
| Verifiable releases are built by the release workflow | Holds for workflow design | Exact-SHA CI gate, reusable build workflows, egress restrictions, signatures, attestations, and SBOMs are present. This review did not independently verify a released artifact. |

The next review is due by **2027-10-21**, and earlier if the threat model changes, a new process or release channel is added, or the F-1 hardening is changed.
