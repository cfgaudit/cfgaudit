# Governance

cfgaudit is maintained by one person. This page says who holds which access, what the roles are, and how changes get in.

## Maintainers

| Maintainer | GitHub | Access |
|---|---|---|
| Nicolai Ehrhardt | [@predictor2718](https://github.com/predictor2718) | Owner of the `cfgaudit` GitHub organization: admin on [cfgaudit/cfgaudit](https://github.com/cfgaudit/cfgaudit) and [cfgaudit/homebrew-tap](https://github.com/cfgaudit/homebrew-tap), the repository secrets (`HOMEBREW_TAP_TOKEN`), the `ghcr.io/cfgaudit/cfgaudit` container package and the GitHub Marketplace listing. Owner of the [gitlab.com/cfgaudit](https://gitlab.com/cfgaudit) group, which publishes the GitLab CI/CD Catalog components. Maintainer of the OpenSSF Best Practices entry and the Codecov project. |

Nobody else has write access to any of these. The organization requires two-factor authentication, and new members get read access by default.

Release signing uses no long-lived key: archives and the image are signed keylessly by the build workflows through GitHub's OIDC token and Sigstore (see [docs/design.md](docs/design.md#release-pipeline)). The GitLab push token is held by the maintainer and is not stored in either repository.

## Roles

- **Maintainer**: reviews and merges pull requests, triages issues and security reports, cuts releases, and holds the access listed above. Responds to vulnerability reports within the timeframes in [SECURITY.md](SECURITY.md).
- **Contributor**: anyone who opens an issue or a pull request. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md); a pull request is merged once the maintainer approves it and the required checks pass.

## How changes are made

- Every change starts as an issue and lands through a pull request against `main`; direct pushes to `main` are blocked, also for administrators.
- A pull request merges only when the required checks pass (build, lint, tests, govulncheck, zizmor). Merges are squash merges.
- Decisions on scope, new rules and severities are the maintainer's, made in the open on the issue or pull request.
- Releases are cut by the maintainer by tagging a commit whose CI passed on `main`; the release workflows refuse any other commit.

## Changes to this document

Adding a maintainer or changing access is done through a pull request to this file, so the list stays the record of who holds what.
