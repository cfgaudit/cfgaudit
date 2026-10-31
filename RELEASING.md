# Releasing cfgaudit

The steps a maintainer follows for a release `vX.Y.Z`, in order. The build and publishing are automated by the tag; this list covers what is not. Who may cut a release is in [GOVERNANCE.md](GOVERNANCE.md), and how the release pipeline is built is in [docs/design.md](docs/design.md#release-pipeline).

## Before the release

1. **Open bugs.** Go through the open `bug` issues and decide which ones the release waits for.
2. **False positives on real repositories.** Run every new or changed rule, and every newly scanned file or surface, against public repositories that contain the relevant agent configuration. Compare the new build with the last release, from an empty directory so no `.cfgaudit.yml` is picked up, and look at every finding the new build adds. Fix what is wrong before tagging, and note in the pin pull request what was measured.
3. **Precision of new and changed rules.** Step 2 shows where a rule fires. This step checks whether those findings are worth reporting and whether the rule's premise holds. For every new or changed rule:
   - **Sample.** Take 20 random findings from the false-positive run, from different repositories where there are enough. Take 50 for a rule that an article, a talk or an advisory quotes. Judge each finding in the context of its repository: a real problem, harmless in that context, or wrong.
   - **Premise.** Check what the rule claims against a primary source: the agent's documentation, its source or changelog, or a measurement on the released agent. The rule's own page, a third-party write-up or another scanner do not count. A rule whose premise does not hold is not released, even if every finding matches its page. For example, the agent may already block what the rule warns about, or the setting may not do what the page says.
   - **Result.** Note in the pin pull request how many findings were real, harmless or wrong, and which source confirmed the premise. If more than 4 of 20 findings (or 10 of 50) are wrong, fix the rule, lower its severity, or hold it back from the release.
4. **AVE mapping.** For each rule added since the last release, decide whether it has a clean AVE behavioral class. If it does, add it to `aveByRule` in `cmd/cfgaudit/avemap.go` and to [docs/cfgaudit-to-ave.md](docs/cfgaudit-to-ave.md); if not, record why it stays unmapped. Check whether AVE published new records that change an existing mapping.
5. **Rule descriptions.** Re-read the README rule table and the `docs/rules/` pages of new and changed rules against what the rules now report.
6. **Project documentation.** Check the README, the pages in `docs/` and the project documents against the code, the workflows and the repository settings. The project documents are CONTRIBUTING, SECURITY, TESTING, GOVERNANCE, RELEASING, ROADMAP and `docs/design.md`.
   - **Code:** flags, exit codes, output formats, defaults and the scanned files.
   - **Workflows:** the jobs and their triggers, required checks and gates.
   - **Repository settings:** branch protection, rulesets, environments, who may do what.
   - **AI assistance:** it may find candidate mismatches. A maintainer verifies every reported mismatch against the source before changing anything, and a claim the assistant could not point to in the source is not acted on.
   - **Result:** fix the mismatches in a pull request before the pin pull request, or file an issue for one that needs more work and decide whether the release waits for it.
7. **Version pins.** Open a pull request `chore: pin the distribution at X.Y.Z` that moves every pinned version to the new one:
   - `VERSION` in `bin/cfgaudit`
   - `version` in `.claude-plugin/plugin.json`
   - the default `image` in `action.yml`
   - the default version in both GitLab component templates under `templates/`
   - the component examples in the README

   `grep` for the previous version afterwards; no pin may be left. The pull request touches sensitive paths and needs the `sensitive-paths-reviewed` label. Merge it and wait for CI on `main`.

## Cutting the release

8. **Tag.** Create an annotated tag on the pin commit on `main` and push it:

   ```sh
   git tag -a vX.Y.Z -m "cfgaudit X.Y.Z" <commit>
   git push origin vX.Y.Z
   ```

   The Release and Docker workflows refuse a commit whose CI did not pass. Before anything is published, the Release workflow runs every archive on its platform and the Docker workflow runs the image, both checking the version and a fixture scan. They then build the archives, checksums, SBOMs and the container image, sign them with build provenance, create the GitHub release and update the Homebrew cask in `cfgaudit/homebrew-tap`. Check that exactly one run of each workflow ran for the tag and that both succeeded.
9. **Release notes.** Above the generated changelog, write the hand-written part:
   - **Can turn a passing pipeline red**: new rules at `error`, stricter checks, new exit-code cases.
   - **Output changes**: changed messages, paths, fingerprints or report fields that make existing findings show up as new.
   - **False positives fixed**, if any are worth naming.
   - Thanks to external contributors by handle.
   - The closing line: "If cfgaudit is useful to you, a star on GitHub helps other people find it."

   Name every security advisory the release fixes.

## After the release

10. **Check what was published.** The release has all assets and `checksums.txt` matches them; `ghcr.io/cfgaudit/cfgaudit` carries `X.Y.Z`, `X.Y` and `latest` on the same digest; the downloaded binary prints `cfgaudit X.Y.Z`; the Homebrew cask is at `X.Y.Z`. The verification commands are in [Verifying a release](README.md#verifying-a-release).
11. **Move the Action tag.** Point the floating `v1` tag at the release commit and force-push it, so `uses: cfgaudit/cfgaudit@v1` picks up the release:

   ```sh
   git tag -f v1 vX.Y.Z^{commit}
   git push -f origin v1
   ```

12. **PyPI.** After the Release workflow, the PyPI workflow builds the wheels from the release archives, smoke-tests them on each platform and waits for approval in the `pypi` environment. Approve it, then check that `pipx install cfgaudit==X.Y.Z` installs the release.
13. **GitLab.** Push `main`, the new tag and `v1` to [gitlab.com/cfgaudit/cfgaudit](https://gitlab.com/cfgaudit/cfgaudit). Check `main` there, not only the tag list: the mirror is not updated automatically and has lagged behind before. When its pipelines for `main`, `vX.Y.Z` and `v1` are green, create the GitLab release on `vX.Y.Z`; the release is what publishes the component version to the CI/CD Catalog.
14. **Website.** [cfgaudit.github.io](https://cfgaudit.github.io) is generated from the latest release by a daily build. Check the next day that it shows the new version and rules.
15. **Advisories.** Publish any security advisory the release fixes, if it is not public yet.
16. **AVE crosswalk.** If step 4 changed mappings, or AVE itself changed, send the updated crosswalk upstream.
