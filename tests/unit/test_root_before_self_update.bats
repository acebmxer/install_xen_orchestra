#!/usr/bin/env bats
# main() refuses root before self_update_script runs git in the checkout:
# a sudo run used to fetch as root first, leaving root-owned files in .git
# that broke every later normal run's self-update.

setup() {
    load '../helpers/mock_helpers'
    load_script

    CALLS="$BATS_TEST_TMPDIR/calls.log"
    : > "$CALLS"

    # Stand in for running under sudo: check_not_root refuses, as it does
    # when EUID is 0 (which a test can't set).
    check_not_root() { echo "check_not_root" >> "$CALLS"; exit 1; }
    self_update_script() { echo "self_update_script" >> "$CALLS"; }
    acquire_lock() { echo "acquire_lock" >> "$CALLS"; }
    show_help() { echo "show_help" >> "$CALLS"; }
    run_menu() { echo "run_menu" >> "$CALLS"; }
    show_status() { echo "show_status" >> "$CALLS"; }
}

@test "root is refused before self-update runs" {
    run main --status
    [ "$status" -eq 1 ]
    [ "$(cat "$CALLS")" = "check_not_root" ]
}

@test "root is refused before self-update for the interactive menu too" {
    run main
    [ "$status" -eq 1 ]
    [ "$(cat "$CALLS")" = "check_not_root" ]
}

@test "--help still skips the root check and self-update" {
    run main --help
    [ "$status" -eq 0 ]
    [ "$(cat "$CALLS")" = "show_help" ]
}
