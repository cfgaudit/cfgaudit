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
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/cfgaudit /usr/local/bin/cfgaudit
# Run unprivileged (dockle CIS-DI-0001). cfgaudit only reads the config files
# mounted into the container: the GitHub Action captures the report via host-side
# shell redirection, so the container never writes to the mount. 65532 is the
# conventional "nonroot" uid and needs no adduser on Alpine.
USER 65532:65532
ENTRYPOINT ["cfgaudit"]
