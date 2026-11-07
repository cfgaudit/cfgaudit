#!/usr/bin/env bash
# Copyright the cfgaudit contributors
# SPDX-License-Identifier: Apache-2.0
#
# Installs the ShellCheck release pinned in ci.yml into a directory, after
# checking it against the pinned digest (#1445). ShellCheck publishes no
# checksum file; the digest is the release asset's sha256.
#
# Usage: SHELLCHECK_VERSION=... SHELLCHECK_SHA256=... install-shellcheck.sh <dir>
set -euo pipefail

dir=${1:?usage: install-shellcheck.sh <dir>}
version=${SHELLCHECK_VERSION:?SHELLCHECK_VERSION is not set}
sha256=${SHELLCHECK_SHA256:?SHELLCHECK_SHA256 is not set}

archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
curl -sSfLo "$archive" \
  "https://github.com/koalaman/shellcheck/releases/download/v${version}/shellcheck-v${version}.linux.x86_64.tar.xz"
echo "$sha256  $archive" | sha256sum -c -
mkdir -p "$dir"
tar -xJf "$archive" -C "$dir" --strip-components=1 "shellcheck-v${version}/shellcheck"
"$dir/shellcheck" --version
