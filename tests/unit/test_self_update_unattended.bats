#!/usr/bin/env bats
# Tests for self_update_script() in install-xen-orchestra.sh. Regression: under
# --non-interactive, confirm_or_skip auto-confirmed the "Reset to origin?"
# prompt after a failed fast-forward, so an unattended (cron) run ran
# `reset --hard` and `clean -fd` and discarded local work in the checkout.

setup() {
    load '../helpers/mock_helpers'
    load_script

    WORK=$(mktemp -d)
    export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid
    export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid

    git init -q --bare "$WORK/origin.git"
    git clone -q "$WORK/origin.git" "$WORK/seed" 2>/dev/null
    git -C "$WORK/seed" checkout -q -b main
    echo base > "$WORK/seed/file"
    git -C "$WORK/seed" add file
    git -C "$WORK/seed" commit -q -m base
    git -C "$WORK/seed" push -q origin main

    git clone -q -b main "$WORK/origin.git" "$WORK/checkout"

    # Diverge: one commit upstream, a different one locally.
    echo upstream > "$WORK/seed/upstream"
    git -C "$WORK/seed" add upstream
    git -C "$WORK/seed" commit -q -m upstream
    git -C "$WORK/seed" push -q origin main
    echo local > "$WORK/checkout/local"
    git -C "$WORK/checkout" add local
    git -C "$WORK/checkout" commit -q -m local

    SCRIPT_DIR="$WORK/checkout"
    XO_NO_SELF_UPDATE=0
}

teardown() {
    rm -rf "$WORK"
}

@test "non-interactive run does not reset a diverged checkout" {
    NON_INTERACTIVE=true
    echo untracked > "$SCRIPT_DIR/notes.txt"
    local before
    before=$(git -C "$SCRIPT_DIR" rev-parse HEAD)

    run self_update_script
    [ "$status" -eq 0 ]
    [[ "$output" == *"not resetting"* ]]
    [ "$(git -C "$SCRIPT_DIR" rev-parse HEAD)" = "$before" ]
    [ -f "$SCRIPT_DIR/local" ]
    [ -f "$SCRIPT_DIR/notes.txt" ]
}
