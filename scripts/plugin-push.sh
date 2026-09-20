#!/bin/bash
# Push a plugin folder's changes from this repo to the standalone xo-plugins
# repo (https://github.com/acebmxer/xo-plugins), keeping the two in sync.
#
# Syncs to the matching branch: run from dev, it updates xo-plugins' dev;
# run from main (after a release PR merges here), it updates xo-plugins'
# main. This keeps xo-plugins' main release-only, same as this repo, so
# unreleased plugin work never reaches it early.
#
# A plain `git subtree push` doesn't work here: xo-plugins holds two
# plugins on the same branch, and subtree push does a raw ref push of a
# freshly split, single-plugin history -- it has no way to merge that in
# alongside the other plugin's folder without clobbering it. So this
# script does the merge on the xo-plugins side instead: split this
# plugin's history locally, then pull that split into a temporary clone of
# xo-plugins (which merges cleanly, leaving the other plugin's folder
# untouched) and push.
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
split_branch="tmp-plugin-push-${plugin_name}"

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

git subtree split --prefix="${plugin_dir}" -b "${split_branch}" >/dev/null

tmp_clone="$(mktemp -d)"
trap 'cd "${repo_root}"; git branch -D "${split_branch}" >/dev/null 2>&1 || true; rm -rf "${tmp_clone}"' EXIT

git clone -q "${plugins_remote_url}" "${tmp_clone}"
cd "${tmp_clone}"
git checkout -q "${current_branch}"
git remote add source "${repo_root}"
git fetch -q source "${split_branch}"
git subtree pull --prefix="${plugin_name}" source "${split_branch}" \
    -m "sync: pull ${plugin_name} from install_xen_orchestra (${current_branch})"
git push -q origin "${current_branch}"

echo "Pushed ${plugin_name} to ${plugins_remote_url} (${current_branch})"
