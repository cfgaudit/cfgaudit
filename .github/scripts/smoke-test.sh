#!/usr/bin/env bash
# Copyright the cfgaudit contributors
# SPDX-License-Identifier: Apache-2.0
#
# Smoke test of a packaged cfgaudit (#1065, #1083): a release archive or a
# wheel, run the way users run it.
#
#   smoke-test.sh VERSION COMMAND...
#
# COMMAND is how to start cfgaudit, for example `./cfgaudit` or
# `venv/bin/cfgaudit`. Checks that `--version` prints `cfgaudit VERSION` and
# that a scan of a project holding the CFG004 fixture exits 1 and reports
# CFG004. Run it from the repository root.
set -euo pipefail

want=$1
shift
fixture=testdata/settings/invalid/CFG004_bypass_permissions.json

version=$("$@" --version)
echo "$version"
if [ "$version" != "cfgaudit $want" ]; then
  echo "::error::expected version $want, got: $version"
  exit 1
fi

proj=$(mktemp -d)
mkdir -p "$proj/.claude"
cp "$fixture" "$proj/.claude/settings.json"
code=0
report=$("$@" --claude-version 2.1.0 --format json "$proj") || code=$?
if [ "$code" != 1 ]; then
  echo "$report"
  echo "::error::scanning the CFG004 fixture exited $code, expected 1 (findings)"
  exit 1
fi
if ! grep -qE '"RuleID": *"CFG004"' <<< "$report"; then
  echo "$report"
  echo "::error::scanning the CFG004 fixture reported no CFG004 finding"
  exit 1
fi
echo "smoke test passed: cfgaudit $want starts and reports CFG004"
