#!/usr/bin/env bash
# Copyright the cfgaudit contributors
# SPDX-License-Identifier: Apache-2.0
#
# Runs ShellCheck on every tracked shell script outside testdata (#1446): each
# *.sh file and each file with a sh or bash shebang, so a script only a release
# or a schedule uses is checked like the rest, and a new one needs no list.
# ShellCheck takes the dialect from the shebang and fails a file without one.
# --norc keeps a local .shellcheckrc from changing the result; an exception
# belongs next to the line it excuses, with its reason.
#
# Usage: lint-shell.sh (from the repository root, shellcheck on PATH)
set -euo pipefail

files=()
while IFS= read -r -d '' file; do
  [ -f "$file" ] || continue
  first=
  IFS= read -r first <"$file" || true
  if [[ $file == *.sh || $first =~ ^#!.*[/[:space:]](ba)?sh([[:space:]]|$) ]]; then
    files+=("$file")
  fi
done < <(git ls-files -z -- . ':(exclude,glob)**/testdata/**')

if [ "${#files[@]}" -eq 0 ]; then
  echo "lint-shell: no shell scripts found" >&2
  exit 1
fi
printf 'lint-shell: %s\n' "${files[@]}"
shellcheck --norc "${files[@]}"
