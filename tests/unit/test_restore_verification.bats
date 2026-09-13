#!/usr/bin/env bats
# Tests for verify_backup_integrity() and restore_xo()'s use of it.

setup() {
    load '../helpers/mock_helpers'
    load_script

    BACKUP_TEST_DIR=$(mktemp -d)
}

teardown() {
    rm -rf "$BACKUP_TEST_DIR"
}

@test "a complete backup with no git repo passes" {
    mkdir -p "$BACKUP_TEST_DIR/xo-backup-20260101_000000"
    touch "$BACKUP_TEST_DIR/xo-backup-20260101_000000/package.json"

    run verify_backup_integrity "$BACKUP_TEST_DIR/xo-backup-20260101_000000"
    [ "$status" -eq 0 ]
}

@test "a backup missing package.json fails" {
    mkdir -p "$BACKUP_TEST_DIR/xo-backup-20260101_000000"
    # No package.json -- as if the copy was interrupted before it got there.

    run verify_backup_integrity "$BACKUP_TEST_DIR/xo-backup-20260101_000000"
    [ "$status" -ne 0 ]
    [[ "$output" == *"package.json"* ]]
}

@test "a backup with a working git repo passes" {
    local dir="$BACKUP_TEST_DIR/xo-backup-20260101_000000"
    mkdir -p "$dir"
    touch "$dir/package.json"
    git -C "$dir" init -q
    git -C "$dir" config user.email "test@example.com"
    git -C "$dir" config user.name "test"
    git -C "$dir" commit -q --allow-empty -m "init"

    # See the "broken .git directory" test below for why this needs a real
    # sudo, not mock_helpers' blanket `sudo() { true; }` stub. Strips a
    # leading "-u <user>" (the only form verify_backup_integrity uses) and
    # runs the rest directly, as this same test-runner user.
    # shellcheck disable=SC2317
    sudo() {
        if [[ "$1" == "-u" ]]; then shift 2; fi
        "$@"
    }
    export -f sudo

    run verify_backup_integrity "$dir"
    [ "$status" -eq 0 ]
}

@test "a backup with a broken .git directory fails" {
    local dir="$BACKUP_TEST_DIR/xo-backup-20260101_000000"
    mkdir -p "$dir/.git"
    touch "$dir/package.json"
    # A .git directory present but empty -- rev-parse HEAD has nothing to read.

    # mock_helpers' global `sudo() { true; }` stub would make this pass
    # regardless -- the ownership check here specifically needs a real
    # sudo -u re-exec (git's own "dubious ownership" safety check is what
    # this call is for), so this test overrides it with one that actually
    # runs the command instead of swallowing it.
    # shellcheck disable=SC2317
    sudo() {
        if [[ "$1" == "-u" ]]; then shift 2; fi
        "$@"
    }
    export -f sudo

    run verify_backup_integrity "$dir"
    [ "$status" -ne 0 ]
    [[ "$output" == *"HEAD could not be read"* ]]
}

@test "a path that is not a directory fails" {
    touch "$BACKUP_TEST_DIR/not-a-dir"

    run verify_backup_integrity "$BACKUP_TEST_DIR/not-a-dir"
    [ "$status" -ne 0 ]
}

@test "restore_xo refuses an incomplete backup and does not touch INSTALL_DIR" {
    BACKUP_DIR="$BACKUP_TEST_DIR"
    mkdir -p "$BACKUP_DIR/xo-backup-20260101_000000"
    # No package.json: this backup is incomplete.

    INSTALL_DIR=$(mktemp -d)
    echo "still here" > "$INSTALL_DIR/marker"
    NON_INTERACTIVE=true
    LIST_BACKUPS_ONLY=false

    run restore_xo
    [ "$status" -ne 0 ]
    [[ "$output" == *"does not look like a complete backup"* ]]
    # INSTALL_DIR must be untouched -- the refusal has to happen before the
    # destructive rm -rf, not after.
    [ -f "$INSTALL_DIR/marker" ]

    rm -rf "$INSTALL_DIR"
}

@test "--list-backups lists backups and tags an incomplete one, without prompting" {
    BACKUP_DIR="$BACKUP_TEST_DIR"
    mkdir -p "$BACKUP_DIR/xo-backup-20260101_000000"
    touch "$BACKUP_DIR/xo-backup-20260101_000000/package.json"
    mkdir -p "$BACKUP_DIR/xo-backup-20260102_000000"
    # This second one is left incomplete on purpose.

    LIST_BACKUPS_ONLY=true

    run restore_xo
    [ "$status" -eq 0 ]
    [[ "$output" == *"xo-backup-20260101_000000"* ]]
    [[ "$output" == *"xo-backup-20260102_000000"* ]]
    [[ "$output" == *"INCOMPLETE/CORRUPT"* ]]
}
