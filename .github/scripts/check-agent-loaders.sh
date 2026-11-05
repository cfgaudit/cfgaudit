#!/usr/bin/env bash
# Copyright the cfgaudit contributors
# SPDX-License-Identifier: Apache-2.0

# Compares the loader files of each agent in a config file between the reviewed
# release and the latest one (#1443), and writes one diff per changed file under
# the output directory. Only reads upstream files, and never runs them. With
# DRY_RUN=true it prints the issue text instead of opening or updating an issue.
#
# Usage: check-agent-loaders.sh <config> <output directory>
#
# A failed request fails the run: an outage says nothing about the loaders.

set -euo pipefail

config=${1:?usage: check-agent-loaders.sh <config> <output directory>}
out=${2:?usage: check-agent-loaders.sh <config> <output directory>}
run_url=${RUN_URL:-}

# The contents of a file at a ref, or nothing when the ref does not have it.
file_at() { # repo path ref output
  local err
  err=$(mktemp)
  if gh api -H "Accept: application/vnd.github.raw" "repos/$1/contents/$2?ref=$3" >"$4" 2>"$err"; then
    rm -f "$err"
    return 0
  fi
  if grep -q 'HTTP 404' "$err"; then
    : >"$4"
    rm -f "$err"
    return 0
  fi
  cat "$err" >&2
  rm -f "$err"
  return 1
}

# Opens the issue, or brings an open one with the same title up to date.
report() { # title body-file
  local title=$1 body=$2 number
  if [ "${DRY_RUN:-}" = true ]; then
    echo "--- $title"
    cat "$body"
    return
  fi
  number=$(gh issue list --state open --search "\"$title\" in:title" --json number,title \
    --jq "map(select(.title == \"$title\")) | .[0].number // empty")
  if [ -n "$number" ]; then
    gh issue edit "$number" --body-file "$body"
    echo "updated issue #$number: $title"
  else
    gh issue create --title "$title" --label enhancement --label tests --body-file "$body"
    echo "opened issue: $title"
  fi
}

jq -c '.agents[]' "$config" | while read -r entry; do
  agent=$(jq -r .agent <<<"$entry")
  repo=$(jq -r .repo <<<"$entry")
  reviewed=$(jq -r .reviewed_tag <<<"$entry")
  latest=$(gh api "repos/$repo/releases/latest" --jq .tag_name)
  # A tag comes from upstream and ends up in a URL and in an issue.
  if ! [[ $latest =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]]; then
    echo "::error::$agent: unexpected release tag"
    exit 1
  fi
  if [ "$latest" = "$reviewed" ]; then
    echo "$agent: $reviewed is the latest release"
    continue
  fi

  mkdir -p "$out/$agent"
  changed=()
  while read -r path; do
    old=$(mktemp)
    new=$(mktemp)
    file_at "$repo" "$path" "$reviewed" "$old"
    file_at "$repo" "$path" "$latest" "$new"
    if ! cmp -s "$old" "$new"; then
      changed+=("$path")
      diff -u --label "$reviewed/$path" --label "$latest/$path" "$old" "$new" \
        >"$out/$agent/${path//\//_}.diff" || true
    fi
    rm -f "$old" "$new"
  done < <(jq -r '.files[]' <<<"$entry")

  if [ "${#changed[@]}" -eq 0 ]; then
    echo "$agent: no loader file changed between $reviewed and $latest"
    continue
  fi

  body=$(mktemp)
  {
    echo "\`$repo\` changed files that decide what $agent loads from a repository, between \`$reviewed\` and \`$latest\`:"
    echo
    for path in "${changed[@]}"; do
      echo "- \`$path\`"
    done
    echo
    echo "Compare the change with the discovery in \`cmd/cfgaudit\` and with \`docs/agent-surfaces.yml\`: new or renamed files, precedence, ignore behaviour, trust. Then bump \`reviewed_tag\` in \`.github/agent-loaders.json\`."
    echo
    echo "An empty side in a diff means the file does not exist at that release, so it was moved or removed."
    if [ -n "$run_url" ]; then
      echo
      echo "Diffs: the \`agent-loader-diffs\` artifact of $run_url"
    fi
  } >"$body"
  report "Agent loader changed: $agent since $reviewed" "$body"
  rm -f "$body"
done
