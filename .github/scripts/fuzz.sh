#!/usr/bin/env bash
# Copyright the cfgaudit contributors
# SPDX-License-Identifier: Apache-2.0
#
# Runs one fuzz target and passes it when go test failed only because the fuzz
# time ran out while the engine was still busy (#1135). That failure reads
# "context deadline exceeded" and leaves no input under testdata/fuzz/<Target>/.
# A panic, a failing input or a build error still fails.
#
# Usage: fuzz.sh <package> <target> <fuzztime>
# GO overrides the go binary, for the test.
set -euo pipefail

pkg=${1:?usage: fuzz.sh <package> <target> <fuzztime>}
target=${2:?usage: fuzz.sh <package> <target> <fuzztime>}
fuzztime=${3:?usage: fuzz.sh <package> <target> <fuzztime>}
go=${GO:-go}
corpus="$pkg/testdata/fuzz/$target"

# What the repo already holds, so an input go test writes shows up as new.
list_corpus() { if [ -d "$corpus" ]; then find "$corpus" -type f | sort; fi; }
before=$(list_corpus)

log=$(mktemp)
trap 'rm -f "$log"' EXIT
status=0
"$go" test "$pkg" -run '^$' -fuzz "^${target}\$" -fuzztime "$fuzztime" -fuzzminimizetime 5s 2>&1 | tee "$log" || status=${PIPESTATUS[0]}
[ "$status" -eq 0 ] && exit 0

if [ "$(list_corpus)" != "$before" ]; then
  exit "$status"
fi
# The indented lines between "--- FAIL: <target>" and the next unindented line.
body=$(awk -v t="--- FAIL: $target " '
  index($0, t) == 1 { in_body = 1; next }
  in_body && /^[^ \t]/ { exit }
  in_body { sub(/^[ \t]+/, ""); print }
' "$log")
if [ "$body" = "context deadline exceeded" ]; then
  echo "::warning title=Fuzz $target::the fuzz time ran out while the engine was busy; no failing input was written"
  exit 0
fi
exit "$status"
