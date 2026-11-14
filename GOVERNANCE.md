# Governance

cfgaudit has two maintainers. This page says who holds which access, what the roles are, and how changes get in.

## Maintainers

| Maintainer | GitHub | Access |
|---|---|---|
| Nicolai Ehrhardt | [@predictor2718](https://github.com/predictor2718) | Owner of the `cfgaudit` GitHub organization: admin on [cfgaudit/cfgaudit](https://github.com/cfgaudit/cfgaudit) and [cfgaudit/homebrew-tap](https://github.com/cfgaudit/homebrew-tap), the repository secrets (`HOMEBREW_TAP_TOKEN`), the `ghcr.io/cfgaudit/cfgaudit` container package and the GitHub Marketplace listing. Owner of the [gitlab.com/cfgaudit](https://gitlab.com/cfgaudit) group, which publishes the GitLab CI/CD Catalog components. Maintainer of the OpenSSF Best Practices entry and the Codecov project. |
| | [@luma434](https://github.com/luma434) | Owner of the `cfgaudit` GitHub organization, with the same GitHub access as above. |

Nobody else has write access to any of these. The organization requires two-factor authentication, and new members get read access by default.

Release signing uses no long-lived key: archives and the image are signed keylessly by the build workflows through GitHub's OIDC token and Sigstore (see [docs/design.md](docs/design.md#release-pipeline)). The release workflows accept only a tag signed by a key in `.github/allowed_signers`, so a maintainer adds their tag signing key there in a pull request before their first release. The GitLab push token is held by the maintainer who owns the GitLab group and is not stored in either repository.

## Roles

- **Maintainer**: reviews and merges pull requests, triages issues and security reports, cuts releases, and holds the access listed above. Responds to vulnerability reports within the timeframes in [SECURITY.md](SECURITY.md).
- **Contributor**: anyone who opens an issue or a pull request. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md); a pull request is merged once a maintainer approves it and the required checks pass.

## How changes are made

- Every change starts as an issue and lands through a pull request against `main`; direct pushes to `main` are blocked, also for administrators.
- A pull request merges only when the required checks pass (build, lint, tests on every platform, govulncheck, zizmor). Merges are squash merges.
- Decisions on scope, new rules and severities are the maintainers', made in the open on the issue or pull request.
- Releases are cut by a maintainer with a tag signed by a key in `.github/allowed_signers`, on a commit whose CI passed on `main`; the release workflows refuse any other tag or commit. The steps are in [RELEASING.md](RELEASING.md).

## Granting access

Write or admin access is given only to a person who has contributed to cfgaudit over a period of time and whom a maintainer knows to work carefully, and only the access the role needs. Every new member must have two-factor authentication on GitHub and GitLab; GitHub enforces it for the organization, on GitLab it is checked before access is given. Access that is no longer used is removed, and all access is removed when someone steps down. Changes to the list of maintainers are made in this file, in a pull request.

## Secrets and credentials

- **Prefer no secret.** Signing, provenance and the Codecov upload use GitHub's short-lived OIDC tokens, and workflows use the per-run `GITHUB_TOKEN` with the least permissions each job needs. No signing key exists.
- **The one stored secret** is `HOMEBREW_TAP_TOKEN`, a GitHub Actions repository secret scoped to writing the cask in `cfgaudit/homebrew-tap`. Only the release build job reads it, and that job runs with an egress allowlist. Only the maintainers can read or change repository secrets.
- **The GitLab push token** is created by the maintainer when needed, with the narrowest scope that pushes to `gitlab.com/cfgaudit/cfgaudit`, and is not stored in either repository, in CI, or in git configuration.
- **Rotation.** Stored tokens are given an expiry of at most one year and are rotated before it, and at once when a token may have been exposed (pasted somewhere, a compromised machine, a maintainer leaving). A rotation replaces the secret, then revokes the old token.
- **Never in the repository.** Secrets are not committed; GitHub secret scanning with push protection blocks the common formats. The fake secrets under `testdata/` exist to test the rules that find real ones.

## Changes to this document

Adding a maintainer or changing access is done through a pull request to this file, so the list stays the record of who holds what.
