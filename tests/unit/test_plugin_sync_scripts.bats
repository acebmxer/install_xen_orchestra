#!/usr/bin/env bats
# Tests for scripts/plugin-push.sh and scripts/plugin-pull.sh, which sync
# plugins/<name>/ with the standalone xo-plugins repo via git subtree.
#
# These run entirely against throwaway local repos -- PLUGINS_REMOTE_URL
# points the scripts at a local bare repo instead of the real xo-plugins on
# GitHub, so no network access or credentials are needed.
#
# A plain `git subtree push` was tried first and found to silently clobber
# a sibling plugin's folder when two plugins share a branch -- these tests
# exist so that regression can't come back unnoticed.

setup() {
    TEST_DIR=$(mktemp -d)
    SOURCE="${TEST_DIR}/source"
    REMOTE="${TEST_DIR}/plugins-remote.git"
    REAL_SCRIPTS_DIR="${BATS_TEST_DIRNAME}/../../scripts"

    export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
    export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com
    export PLUGINS_REMOTE_URL="${REMOTE}"

    # A source repo with two plugin folders, on both dev and main (main a
    # commit behind, like a real unreleased dev branch would be).
    mkdir -p "${SOURCE}/plugins/foo" "${SOURCE}/plugins/bar" "${SOURCE}/scripts"
    git -C "${SOURCE}" init -q -b main
    echo "foo v1" > "${SOURCE}/plugins/foo/index.js"
    echo "bar v1" > "${SOURCE}/plugins/bar/index.js"
    git -C "${SOURCE}" add -A
    git -C "${SOURCE}" commit -q -m "init"
    git -C "${SOURCE}" checkout -q -b dev
    cp "${REAL_SCRIPTS_DIR}/plugin-push.sh" "${REAL_SCRIPTS_DIR}/plugin-pull.sh" "${SOURCE}/scripts/"

    # The xo-plugins remote: dev and main, each already holding both
    # plugins as subtrees, same as the real repo.
    # Split each plugin out of the source repo first -- subtree-adding the
    # unfiltered source tree directly (its whole plugins/foo *and*
    # plugins/bar) under a single prefix is the exact bug this fixture
    # needs to avoid reproducing.
    git -C "${SOURCE}" subtree split --prefix=plugins/foo -b split-foo >/dev/null
    git -C "${SOURCE}" subtree split --prefix=plugins/bar -b split-bar >/dev/null

    git init -q --bare "${REMOTE}"
    local import="${TEST_DIR}/import"
    git clone -q "${REMOTE}" "${import}"
    (
        cd "${import}"
        git remote add src "${SOURCE}"
        git fetch -q src split-foo split-bar
        for branch in dev main; do
            # --orphan so each branch starts empty and independent -- a
            # plain checkout -b would fork off whatever the previous loop
            # iteration just imported, and subtree add refuses a prefix
            # that already exists.
            git checkout -q --orphan "${branch}"
            git rm -rqf --ignore-unmatch -- .
            git commit -q --allow-empty -m "init ${branch}"
            git subtree add --prefix=foo src split-foo -m "import foo" >/dev/null
            git subtree add --prefix=bar src split-bar -m "import bar" >/dev/null
            git push -q origin "${branch}"
        done
    )
    rm -rf "${import}"

    git -C "${SOURCE}" branch -D split-foo split-bar >/dev/null
    cd "${SOURCE}"
    git checkout -q dev
}

teardown() {
    rm -rf "${TEST_DIR}"
}

@test "plugin-push.sh syncs a changed plugin without touching its sibling's folder" {
    echo "foo v2" > "${SOURCE}/plugins/foo/index.js"
    git -C "${SOURCE}" commit -q -am "update foo"

    run bash "${SOURCE}/scripts/plugin-push.sh" foo
    [ "$status" -eq 0 ]

    local check="${TEST_DIR}/check"
    git clone -q --branch dev "${REMOTE}" "${check}"
    [ "$(cat "${check}/foo/index.js")" = "foo v2" ]
    [ "$(cat "${check}/bar/index.js")" = "bar v1" ]
}

@test "plugin-push.sh only updates the branch it was run from" {
    echo "foo v2" > "${SOURCE}/plugins/foo/index.js"
    git -C "${SOURCE}" commit -q -am "update foo on dev"
    run bash "${SOURCE}/scripts/plugin-push.sh" foo
    [ "$status" -eq 0 ]

    local check="${TEST_DIR}/check"
    git clone -q --branch main "${REMOTE}" "${check}"
    [ "$(cat "${check}/foo/index.js")" = "foo v1" ]
}

@test "plugin-push.sh refuses to run from a branch that isn't dev or main" {
    git -C "${SOURCE}" checkout -q -b feature/something

    run bash "${SOURCE}/scripts/plugin-push.sh" foo
    [ "$status" -ne 0 ]
    [[ "$output" == *"Refusing to sync from branch"* ]]
}

@test "plugin-push.sh errors on a plugin folder that doesn't exist" {
    run bash "${SOURCE}/scripts/plugin-push.sh" nonexistent-plugin
    [ "$status" -ne 0 ]
    [[ "$output" == *"No such plugin folder"* ]]
}

@test "plugin-pull.sh copies a change from xo-plugins without committing" {
    local edit="${TEST_DIR}/edit"
    git clone -q --branch dev "${REMOTE}" "${edit}"
    echo "bar v2 from xo-plugins" > "${edit}/bar/index.js"
    git -C "${edit}" commit -q -am "edit bar directly in xo-plugins"
    git -C "${edit}" push -q origin dev

    run bash "${SOURCE}/scripts/plugin-pull.sh" bar
    [ "$status" -eq 0 ]
    [ "$(cat "${SOURCE}/plugins/bar/index.js")" = "bar v2 from xo-plugins" ]

    # Not committed -- left for review, per the script's own contract.
    run git -C "${SOURCE}" status --porcelain -- plugins/bar
    [ -n "$output" ]
}

@test "plugin-pull.sh refuses to run from a branch that isn't dev or main" {
    git -C "${SOURCE}" checkout -q -b feature/something

    run bash "${SOURCE}/scripts/plugin-pull.sh" bar
    [ "$status" -ne 0 ]
    [[ "$output" == *"Refusing to sync from branch"* ]]
}

@test "plugin-pull.sh errors on a plugin folder that doesn't exist locally" {
    run bash "${SOURCE}/scripts/plugin-pull.sh" nonexistent-plugin
    [ "$status" -ne 0 ]
    [[ "$output" == *"No such plugin folder"* ]]
}
