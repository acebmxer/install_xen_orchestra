#!/usr/bin/env bats
# Integration smoke tests — run inside Docker containers.
# These tests verify that the script is well-formed and that the new flags work
# without performing any actual system installation.

@test "--help exits 0 and output contains 'Usage'" {
    XO_NO_SELF_UPDATE=1 run bash install-xen-orchestra.sh --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage"* ]]
}

@test "--install --non-interactive --dry-run exits 0 and prints [DRY-RUN] lines" {
    XO_NO_SELF_UPDATE=1 run bash install-xen-orchestra.sh --install --non-interactive --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"[DRY-RUN]"* ]]
}

@test "shellcheck passes at error level" {
    run shellcheck -S error install-xen-orchestra.sh
    [ "$status" -eq 0 ]
}

@test "sample-xo-config.cfg contains CONFIG_VERSION=1" {
    run grep "^CONFIG_VERSION=1" sample-xo-config.cfg
    [ "$status" -eq 0 ]
}
