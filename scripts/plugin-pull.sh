#!/bin/bash
# Pull a plugin folder's changes from the standalone xo-plugins repo
# (https://github.com/acebmxer/xo-plugins) back into this repo.
#
# Pulls from the matching branch: run from dev, it reads xo-plugins' dev;
# run from main, it reads xo-plugins' main.
#
# This copies the plugin's files over plugins/<name>/ here. It does NOT
# commit -- review the diff with `git status` / `git diff` and commit it
# yourself once it looks right.
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

current_branch="$(git -C "${repo_root}" rev-parse --abbrev-ref HEAD)"
if [[ ! " ${allowed_branches[*]} " == *" ${current_branch} "* ]]; then
    echo "Refusing to sync from branch '${current_branch}' -- only ${allowed_branches[*]} are mirrored to xo-plugins." >&2
    exit 1
fi

tmp_clone="$(mktemp -d)"
trap 'rm -rf "${tmp_clone}"' EXIT

git clone -q --branch "${current_branch}" --depth 1 "${plugins_remote_url}" "${tmp_clone}"

if [[ ! -d "${tmp_clone}/${plugin_name}" ]]; then
    echo "No such plugin folder in xo-plugins (${current_branch}): ${plugin_name}" >&2
    exit 1
fi

rsync -a --delete --exclude .git "${tmp_clone}/${plugin_name}/" "${repo_root}/${plugin_dir}/"

echo "Pulled ${plugin_name} from ${plugins_remote_url} (${current_branch}) into ${plugin_dir}/"
echo "Review with: git -C '${repo_root}' status -- '${plugin_dir}'"
echo "Then commit it yourself if it looks right."
