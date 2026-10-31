#!/usr/bin/env bash
# Copyright the cfgaudit contributors
# SPDX-License-Identifier: Apache-2.0
#
# Fails when a function nothing reachable from cmd/cfgaudit calls is not in
# .github/deadcode-allow.txt, or when an entry there is no longer reported
# (#1099). golangci-lint's unused covers unexported code only; an exported
# function that only tests still call would otherwise stay in the tree.
#
# Usage: deadcode-check.sh <deadcode binary>
set -euo pipefail

deadcode=${1:?usage: deadcode-check.sh <deadcode binary>}
allow=.github/deadcode-allow.txt

reported=$("$deadcode" -f '{{range .Funcs}}{{$.Path}}.{{.Name}}{{"\n"}}{{end}}' ./cmd/cfgaudit | sort -u)
allowed=$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$allow" | sort -u)

new=$(comm -23 <(printf '%s\n' "$reported" | sed '/^$/d') <(printf '%s\n' "$allowed" | sed '/^$/d'))
stale=$(comm -13 <(printf '%s\n' "$reported" | sed '/^$/d') <(printf '%s\n' "$allowed" | sed '/^$/d'))

status=0
if [ -n "$new" ]; then
  echo "Unreachable from cmd/cfgaudit; remove them, or list them in $allow with a reason:"
  printf '  %s\n' $new
  status=1
fi
if [ -n "$stale" ]; then
  echo "Listed in $allow but no longer reported; remove the entries:"
  printf '  %s\n' $stale
  status=1
fi
[ "$status" -eq 0 ] && echo "deadcode: nothing unreachable outside $allow"
exit "$status"
