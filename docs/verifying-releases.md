# Verifying a release

Every release is built by a GitHub Actions workflow that publishes [build provenance](https://slsa.dev/), and the container image is additionally signed with [cosign](https://github.com/sigstore/cosign). Both are keyless — the signing identity *is* the workflow, so a verified artifact provably came from this repository's release pipeline.

From **v1.17.0** on, the release archives and the container image meet [SLSA](https://slsa.dev/spec/v1.0/levels) **Build Level 3**: they are built in reusable workflows (`build-release.yml`, `build-image.yml`) that the tag-triggered workflows only call, so the build workflow signs the provenance. That is the isolation GitHub documents as [SLSA v1 Build Level 3 for artifact attestations](https://docs.github.com/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3). Releases v1.8.0 to v1.16.0 meet Build Level 2: their provenance is signed by `release.yml` and `docker.yml` themselves. `--signer-workflow` below requires the build workflow; drop it for releases before v1.17.0.

**Release archive** — provenance for the archive you downloaded:

```sh
gh attestation verify cfgaudit_1.17.0_linux_amd64.tar.gz -R cfgaudit/cfgaudit \
  --signer-workflow cfgaudit/cfgaudit/.github/workflows/build-release.yml
```

**`checksums.txt`** — verify this too if you check downloads against it (the plugin wrapper in `bin/cfgaudit` does):

```sh
gh attestation verify checksums.txt -R cfgaudit/cfgaudit \
  --signer-workflow cfgaudit/cfgaudit/.github/workflows/build-release.yml
```

**Container image** — provenance and signature, both bound to the image digest rather than a tag, since a tag can be repointed later:

```sh
DIGEST=$(docker buildx imagetools inspect ghcr.io/cfgaudit/cfgaudit:latest --format '{{.Manifest.Digest}}')

gh attestation verify "oci://ghcr.io/cfgaudit/cfgaudit@$DIGEST" -R cfgaudit/cfgaudit \
  --signer-workflow cfgaudit/cfgaudit/.github/workflows/build-image.yml

cosign verify "ghcr.io/cfgaudit/cfgaudit@$DIGEST" \
  --certificate-identity-regexp '^https://github.com/cfgaudit/cfgaudit/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Attestations and the image signature are published from **v1.8.0** onward, the first release built by the signing pipeline; `checksums.txt` is covered from the same release.

**Without the GitHub API**: from v1.8.0 onward, the same attestation is also attached to each release as two assets: `cfgaudit_<version>.sigstore.json`, the Sigstore bundle with the signature, signing certificate and transparency log entry, and `cfgaudit_<version>.intoto.jsonl`, the signed SLSA provenance on its own. One bundle covers all six archives and `checksums.txt`. Verify a download against it with cosign:

```sh
VERSION=<version>   # e.g. the release you downloaded, without the leading v
cosign verify-blob-attestation \
  --bundle "cfgaudit_${VERSION}.sigstore.json" \
  --type slsaprovenance1 \
  --certificate-identity-regexp '^https://github\.com/cfgaudit/cfgaudit/\.github/workflows/(build-)?release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "cfgaudit_${VERSION}_linux_amd64.tar.gz"
```

The identity pins the signer to this repository's release workflow running on a tag, so a bundle signed by any other workflow or repository fails, as does a file whose digest is not in the provenance. The regex accepts `release.yml`, which signed releases before v1.17.0, and `build-release.yml`, which signs them from v1.17.0 on; use only the latter to require Build Level 3.

**Rebuilding a release**: the binaries are reproducible. Building the tag with the Go version recorded in the release binary and the release flags gives a byte-identical binary, so you can check a download without trusting the pipeline at all. For example, for the Linux amd64 binary of v1.17.1:

```sh
go version -m cfgaudit | head -1        # the Go version the release used, e.g. go1.24.13
git clone --branch v1.17.1 https://github.com/cfgaudit/cfgaudit.git cfgaudit-src && cd cfgaudit-src
GOTOOLCHAIN=go1.24.13 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -X main.cfgauditVersion=1.17.1" -o cfgaudit-rebuilt ./cmd/cfgaudit
sha256sum cfgaudit-rebuilt ../cfgaudit   # the binary from the release archive
```

Build from a fresh clone of the tag: Go records the commit and whether the working tree is clean in the binary, so a modified checkout or a `git worktree` gives a different hash.

The archives are reproducible too, for releases after v1.19.0: every entry carries the commit time and `root` ownership instead of the build machine's, so rebuilding the tag with GoReleaser (`goreleaser release --clean --skip=publish,sbom`) and the same Go version gives the checksums in `checksums.txt`. The Reproducible build workflow builds the archives on two runners for every push to `main` and fails when they differ.

## A note on SBOMs

The container image carries its SBOM as a signed attestation. The per-archive `.sbom.json` files, by contrast, are published as **plain release assets, not attestations** — deliberately.

Each one lists cfgaudit itself, its two dependencies (`gopkg.in/yaml.v3`, `github.com/BurntSushi/toml`), the Go standard library, and the archive's own digest. That is the same information `go.mod` already makes public, and the archive it describes is covered by provenance — so a swapped SBOM cannot make a tampered archive verify. If you need an SBOM you can trust end to end, use the image attestation, or regenerate one from a verified archive with [syft](https://github.com/anchore/syft).
