#!/usr/bin/env bats
# Tests for check_sudo() in install-xen-orchestra.sh. Regression: it used only
# `sudo -v`, which asks for a password unless every sudoers rule matching the
# user is NOPASSWD -- so a sudo/wheel-group account with NOPASSWD:ALL added
# still failed the check under cron.

setup() {
    load '../helpers/mock_helpers'
    load_script
    DRY_RUN=false
    SUDO_CALLS=$(mktemp)
    export SUDO_CALLS
}

teardown() {
    rm -f "$SUDO_CALLS"
}

@test "passes on sudo -n true without calling sudo -v" {
    # shellcheck disable=SC2317
    sudo() { echo "$*" >> "$SUDO_CALLS"; [[ "$1" == "-n" ]]; }
    export -f sudo

    run check_sudo
    [ "$status" -eq 0 ]
    run cat "$SUDO_CALLS"
    [[ "$output" != *"-v"* ]]
}

@test "falls back to sudo -v when sudo -n true fails" {
    # shellcheck disable=SC2317
    sudo() { echo "$*" >> "$SUDO_CALLS"; [[ "$1" == "-v" ]]; }
    export -f sudo

    run check_sudo
    [ "$status" -eq 0 ]
    run cat "$SUDO_CALLS"
    [[ "$output" == *"-v"* ]]
}

@test "exits with an error when both sudo -n true and sudo -v fail" {
    # shellcheck disable=SC2317
    sudo() { return 1; }
    export -f sudo

    run check_sudo
    [ "$status" -eq 1 ]
    [[ "$output" == *"You need sudo privileges"* ]]
}
