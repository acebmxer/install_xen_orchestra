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

@test "sample-xo-config.cfg is stamped at the script's latest CONFIG_VERSION" {
    # The sample config must advertise the same schema version the script
    # considers current, so a fresh install never needs an immediate migration.
    latest=$(grep -E '^LATEST_CONFIG_VERSION=' install-xen-orchestra.sh | head -n1 | cut -d= -f2)
    [ -n "$latest" ]
    run grep "^CONFIG_VERSION=${latest}" sample-xo-config.cfg
    [ "$status" -eq 0 ]
}

@test "a failed --update that stopped XO names the backup and the restore command (#123)" {
    # Runs the real update_xo with its steps stubbed and the build failing, so
    # every distro in the CI matrix has to print the same report.
    root="$(mktemp -d)"
    XO_TEST_ROOT="$root" run bash tests/helpers/downtime_scenario.sh update build
    [ "$status" -ne 0 ]
    [[ "$output" == *"The update failed, and Xen Orchestra is stopped."* ]]
    [[ "$output" == *"--restore --backup-file xo-backup-"* ]]
    [[ "$output" == *"--non-interactive"* ]]
    # The facts for a bug report, with this image's own distro in them.
    [[ "$output" == *"Include this when you report the problem:"* ]]
    [[ "$output" == *"System:            $(. /etc/os-release; echo "$ID")"* ]]
    rm -rf "$root"
}

@test "a failed --rebuild after the backup gives the same report (#123)" {
    root="$(mktemp -d)"
    XO_TEST_ROOT="$root" run bash tests/helpers/downtime_scenario.sh rebuild build
    [ "$status" -ne 0 ]
    [[ "$output" == *"The rebuild failed, and Xen Orchestra is stopped."* ]]
    [[ "$output" == *"--restore --backup-file xo-backup-"* ]]
    rm -rf "$root"
}

@test "a successful --update prints no failure report (#123)" {
    root="$(mktemp -d)"
    XO_TEST_ROOT="$root" run bash tests/helpers/downtime_scenario.sh update none
    [ "$status" -eq 0 ]
    [[ "$output" != *"is stopped"* ]]
    [[ "$output" != *"--restore"* ]]
    rm -rf "$root"
}
