#!/usr/bin/env bash
# Copyright the cfgaudit contributors
# SPDX-License-Identifier: Apache-2.0
#
# Release gate (#1098): the tag must point at the commit the workflow runs for
# and carry a signature by a key in the allowed signers file.
#
#   verify-release-tag.sh check <git dir> <tag> <sha> <allowed signers file>
#       Checks a tag already present in <git dir>.
#   verify-release-tag.sh gate <repo> <tag> <sha> <default branch>
#       What the workflows run, with this file read from the default branch:
#       requires <sha> to be on the default branch, reads .github/allowed_signers
#       from there through the API, never from the tagged commit, fetches the
#       tag into an empty repository and runs check.
set -euo pipefail

check() {
  local dir=$1 tag=$2 sha=$3 signers=$4 target
  if ! target=$(git -C "$dir" rev-parse --verify --quiet "refs/tags/$tag^{commit}"); then
    echo "::error::Release blocked: tag $tag not found."
    return 1
  fi
  if [ "$target" != "$sha" ]; then
    echo "::error::Release blocked: tag $tag points at $target, not at $sha."
    return 1
  fi
  if [ "$(git -C "$dir" cat-file -t "refs/tags/$tag")" != tag ]; then
    echo "::error::Release blocked: $tag is a lightweight tag; create it with git tag -s (see RELEASING.md)."
    return 1
  fi
  if ! git -C "$dir" -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$signers" verify-tag "$tag"; then
    echo "::error::Release blocked: $tag is not signed by a key in .github/allowed_signers on the default branch; sign it with git tag -s (see RELEASING.md)."
    return 1
  fi
  echo "Tag $tag at $sha is signed by a listed key."
}

gate() {
  local repo=$1 tag=$2 sha=$3 branch=$4 work status
  work=$(mktemp -d)
  # A tag on a commit that never reached the default branch was never reviewed
  # there; "behind" and "identical" mean the commit is part of its history.
  status=$(gh api "repos/$repo/compare/$branch...$sha" --jq .status)
  if [ "$status" != behind ] && [ "$status" != identical ]; then
    echo "::error::Release blocked: $sha is not on $branch (compare status: $status)."
    return 1
  fi
  if ! gh api "repos/$repo/contents/.github/allowed_signers?ref=$branch" \
    -H "Accept: application/vnd.github.raw" > "$work/allowed_signers"; then
    echo "::error::Release blocked: could not read .github/allowed_signers from $branch."
    return 1
  fi
  git init -q "$work/repo"
  git -C "$work/repo" fetch -q --depth=1 "https://github.com/$repo" "+refs/tags/$tag:refs/tags/$tag"
  check "$work/repo" "$tag" "$sha" "$work/allowed_signers"
}

cmd=${1:-}
shift || true
case "$cmd" in
  check) check "$@" ;;
  gate) gate "$@" ;;
  *) echo "usage: verify-release-tag.sh check <dir> <tag> <sha> <signers> | gate <repo> <tag> <sha> <branch>" >&2; exit 2 ;;
esac
