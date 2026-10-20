#!/bin/bash
# Push a plugin folder's changes from this repo to the standalone xo-plugins
# repo (https://github.com/acebmxer/xo-plugins), keeping the two in sync.
#
# Syncs to the matching branch: run from dev, it updates xo-plugins' dev;
# run from main (after a release PR merges here), it updates xo-plugins'
# main. This keeps xo-plugins' main release-only, same as this repo, so
# unreleased plugin work never reaches it early.
#
# This is the mirror image of plugin-pull.sh: it copies the plugin's files
# into a temporary clone of xo-plugins by content, commits if anything
# differs, and pushes. It does not merge history. An earlier version used
# `git subtree`, which conflicted whenever both repos had touched the same
# lines -- and every round-trip sync records the same change as two separate
# commits, so that happened on ordinary version bumps.
set -euo pipefail

allowed_branches=(dev main)

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <plugin-name>" >&2
    echo "  e.g. $0 xo-server-nanokvm" >&2
    exit 1
fi

plugin_name="$1"
# Overridable so tests/unit/test_plugin_sync_scripts.bats can point this at a
# throwaway local repo instead of the real xo-plugins on GitHub.
plugins_remote_url="${PLUGINS_REMOTE_URL:-https://github.com/acebmxer/xo-plugins.git}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
plugin_dir="plugins/${plugin_name}"

if [[ ! -d "${repo_root}/${plugin_dir}" ]]; then
    echo "No such plugin folder: ${plugin_dir}" >&2
    exit 1
fi

cd "${repo_root}"
current_branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ ! " ${allowed_branches[*]} " == *" ${current_branch} "* ]]; then
    echo "Refusing to sync from branch '${current_branch}' -- only ${allowed_branches[*]} are mirrored to xo-plugins." >&2
    exit 1
fi

tmp_clone="$(mktemp -d)"
trap 'rm -rf "${tmp_clone}"' EXIT

git clone -q --branch "${current_branch}" --depth 1 "${plugins_remote_url}" "${tmp_clone}"

# --checksum: compare content, not size + mtime to the second -- see the same
# note in plugin-pull.sh (a same-length edit such as a version bump was skipped).
rsync -a --checksum --delete --exclude .git \
    "${repo_root}/${plugin_dir}/" "${tmp_clone}/${plugin_name}/"

cd "${tmp_clone}"
git add -A -- "${plugin_name}"
if git diff --cached --quiet; then
    echo "${plugin_name} is already in sync with ${plugins_remote_url} (${current_branch})."
    exit 0
fi

git commit -q -m "sync: pull ${plugin_name} from install_xen_orchestra (${current_branch})"
git push -q origin "${current_branch}"

echo "Pushed ${plugin_name} to ${plugins_remote_url} (${current_branch})"
