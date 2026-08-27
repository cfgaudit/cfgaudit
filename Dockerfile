FROM golang:1.26-alpine AS builder
ARG VERSION=dev
WORKDIR /build
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.cfgauditVersion=${VERSION}" \
    -o cfgaudit ./cmd/cfgaudit

FROM alpine:3.24
# Alpine's repos serve only the current patch of a package, so an exact version
# pin breaks the build the moment upstream bumps it — and would fight the Trivy
# base-image freshness gate in ci.yml, which exists to force those bumps.
#
# The upgrade is what keeps the image actually patched. Docker Hub rebuilds
# alpine:3.24 far less often than Alpine publishes security patches, so the base
# image ships whatever package set the last rebuild froze in. CVE-2026-14456 is
# the case in point: fixed in openssl 3.5.8-r0 and served by the 3.24 repo, while
# the alpine:3.24.1 image still carries 3.5.7-r0 and fails the Trivy gate below.
# A plain `apk add libcrypto3` would not help, since apk leaves an already
# installed package alone. DL3017 warns that this makes the build depend on the
# repo's state at build time, which is true, and is the point: the unpinned
# `apk add` in the same command already has that property, and the Trivy gate is what turns a
# stale package set into a failing build rather than a silent one.
# hadolint ignore=DL3018,DL3017
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=builder /build/cfgaudit /usr/local/bin/cfgaudit

# Static identity labels only. The release build passes docker/metadata-action's
# generated labels to `docker build --label`, which *overrides* any LABEL
# declared here — so the dynamic values (version, revision, created) are owned by
# that action and deliberately not restated. What these lines buy is a
# self-describing image for plain `docker build .`, which otherwise carries no
# labels at all, plus `documentation`, which metadata-action does not emit and
# which therefore survives on the published image too.
LABEL org.opencontainers.image.title="cfgaudit" \
      org.opencontainers.image.description="AI agent configuration security auditor - find misconfigurations in Claude Code, Cursor, and other AI tools" \
      org.opencontainers.image.url="https://github.com/cfgaudit/cfgaudit" \
      org.opencontainers.image.source="https://github.com/cfgaudit/cfgaudit" \
      org.opencontainers.image.documentation="https://github.com/cfgaudit/cfgaudit/blob/main/README.md" \
      org.opencontainers.image.vendor="cfgaudit" \
      org.opencontainers.image.licenses="Apache-2.0"
# Run unprivileged (dockle CIS-DI-0001). cfgaudit only reads the config files
# mounted into the container: the GitHub Action captures the report via host-side
# shell redirection, so the container never writes to the mount. 65532 is the
# conventional "nonroot" uid and needs no adduser on Alpine.
USER 65532:65532
ENTRYPOINT ["cfgaudit"]
