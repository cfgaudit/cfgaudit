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
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/cfgaudit /usr/local/bin/cfgaudit
ENTRYPOINT ["cfgaudit"]
