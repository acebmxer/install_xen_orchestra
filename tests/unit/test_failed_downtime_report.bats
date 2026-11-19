#!/usr/bin/env bats
# #123: when --update or --rebuild fails after xo-server was stopped, the script
# says that XO is stopped, names the backup made in this run and the command
# that restores it. Each case runs the real update_xo / rebuild_xo through
# tests/helpers/downtime_scenario.sh, with one stage made to fail.

SCENARIO="${BATS_TEST_DIRNAME}/../helpers/downtime_scenario.sh"

setup() {
    XO_TEST_ROOT="$(mktemp -d)"
    export XO_TEST_ROOT
}

teardown() {
    rm -rf "$XO_TEST_ROOT"
}

# The backup path the failure report names.
reported_backup() {
    sed -n 's/.*A backup of the install as it was before this run is at: //p' <<< "$output"
}

@test "update: a failed build says XO is stopped, names the backup and the restore command" {
    run bash "$SCENARIO" update build
    [ "$status" -ne 0 ]
    [[ "$output" == *"The update failed, and Xen Orchestra is stopped."* ]]
    local path
    path="$(reported_backup)"
    # The named path is the backup this run made, and it exists.
    [[ "$path" == "${XO_TEST_ROOT}/backups/xo-backup-"* ]]
    [ -f "${path}/marker" ]
    # The command names the script by its full path, so it runs from anywhere.
    [[ "$output" == *"run: /"*"/install-xen-orchestra.sh --restore --backup-file $(basename "$path") --non-interactive"* ]]
    [[ "$output" == *"Do not just start the service"* ]]
    # It does not send the user to a half-updated install.
    [[ "$output" != *"Start it again with"* ]]
}

@test "update: the report ends with the facts a bug report needs" {
    run bash "$SCENARIO" update build
    [ "$status" -ne 0 ]
    [[ "$output" == *"Include this when you report the problem:"* ]]
    [[ "$output" == *"Installer:"* ]]
    [[ "$output" == *"System:"* ]]
    [[ "$output" == *"Node.js:"* ]]
    [[ "$output" == *"Branch:            master"* ]]
    [[ "$output" == *"XO commit before:  aaaaaaaaaaaa"* ]]
    [[ "$output" == *"XO commit target:  bbbbbbbbbbbb"* ]]
    [[ "$output" == *"Also copy the error printed above this message."* ]]
    # Last thing printed, so it is the block to copy.
    [[ "$output" == *"Also copy the error printed above this message." ]]
}

@test "update: the facts are printed when the failure came before the backup too" {
    run bash "$SCENARIO" update flush
    [[ "$output" == *"Include this when you report the problem:"* ]]
    [[ "$output" == *"XO commit target:  bbbbbbbbbbbb"* ]]
}

@test "rebuild: the facts name the commit it started from and no target" {
    run bash "$SCENARIO" rebuild build
    [[ "$output" == *"Include this when you report the problem:"* ]]
    [[ "$output" == *"XO commit before:  aaaaaaaaaaaa"* ]]
    [[ "$output" != *"XO commit target:"* ]]
}

@test "the facts block says unknown rather than failing when a value is missing" {
    run bash -c '_XO_SOURCE_ONLY=1 source "$1"; set +e; detect_os() { :; }; unset OS_ID OS_VERSION_ID GIT_BRANCH; PATH=/nonexistent; print_failure_details' _ "${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Node.js:           unknown"* ]]
    [[ "$output" == *"System:            unknown"* ]]
    [[ "$output" == *"Branch:            unknown"* ]]
}

@test "the facts name the distro the script runs on, read from os-release" {
    run bash "$SCENARIO" update build
    local id
    id="$(. /etc/os-release; echo "$ID")"
    [[ "$output" == *"System:            ${id}"* ]]
}

@test "a successful run prints no facts block" {
    run bash "$SCENARIO" update none
    [[ "$output" != *"Include this when you report"* ]]
    run bash "$SCENARIO" rebuild none
    [[ "$output" != *"Include this when you report"* ]]
}

@test "update: a failed git fetch after the backup gives the same report" {
    run bash "$SCENARIO" update pull
    [ "$status" -ne 0 ]
    [[ "$output" == *"The update failed, and Xen Orchestra is stopped."* ]]
    [[ "$output" == *"--restore --backup-file xo-backup-"* ]]
}

@test "update: a failed service start, the last step, gives the same report" {
    run bash "$SCENARIO" update start
    [ "$status" -ne 0 ]
    [[ "$output" == *"The update failed, and Xen Orchestra is stopped."* ]]
    [[ "$output" == *"--restore --backup-file xo-backup-"* ]]
}

@test "update: a failure before the backup says nothing was changed and how to start XO" {
    run bash "$SCENARIO" update flush
    [ "$status" -ne 0 ]
    [[ "$output" == *"The update failed, and Xen Orchestra is stopped."* ]]
    [[ "$output" == *"It failed before the backup was made, so the installation has not been changed."* ]]
    [[ "$output" == *"Start it again with: sudo systemctl start xo-server"* ]]
    [[ "$output" != *"--restore"* ]]
}

@test "update: a backup that itself fails is reported as before the backup was made" {
    run bash "$SCENARIO" update backup
    [ "$status" -ne 0 ]
    [[ "$output" == *"It failed before the backup was made"* ]]
    [[ "$output" != *"--restore"* ]]
}

@test "update: the exit status of the failed step is kept" {
    run bash "$SCENARIO" update build
    [ "$status" -eq 1 ]
}

@test "update: a successful run prints no failure report and restarts the service" {
    run bash "$SCENARIO" update none
    [ "$status" -eq 0 ]
    [[ "$output" == *"Update completed successfully!"* ]]
    [[ "$output" != *"is stopped"* ]]
    [[ "$output" != *"--restore"* ]]
    [[ "$output" != *"Start it again"* ]]
    grep -q "systemctl start xo-server" "${XO_TEST_ROOT}/systemctl.log"
}

@test "a dry run stops nothing, so it never arms the failure report" {
    run bash -c '_XO_SOURCE_ONLY=1 source "$1"; DRY_RUN=true; begin_service_downtime update; [ -z "$STOPPED_FOR" ]' _ "${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
    [ "$status" -eq 0 ]
}

@test "rebuild: a failed clean build says XO is stopped, names the backup and the restore command" {
    run bash "$SCENARIO" rebuild build
    [ "$status" -ne 0 ]
    [[ "$output" == *"The rebuild failed, and Xen Orchestra is stopped."* ]]
    local path
    path="$(reported_backup)"
    [[ "$path" == "${XO_TEST_ROOT}/backups/xo-backup-"* ]]
    [ -f "${path}/marker" ]
    [[ "$output" == *"--restore --backup-file $(basename "$path") --non-interactive"* ]]
}

@test "rebuild: a failure before the backup says nothing was changed and how to start XO" {
    run bash "$SCENARIO" rebuild flush
    [ "$status" -ne 0 ]
    [[ "$output" == *"The rebuild failed, and Xen Orchestra is stopped."* ]]
    [[ "$output" == *"Start it again with: sudo systemctl start xo-server"* ]]
    [[ "$output" != *"--restore"* ]]
}

@test "rebuild: a failed clone starts XO again and does not say it is stopped" {
    run bash "$SCENARIO" rebuild clone
    [ "$status" -ne 0 ]
    [[ "$output" == *"Clone failed. The current installation was left in place."* ]]
    [[ "$output" != *"is stopped"* ]]
    [[ "$output" != *"--restore"* ]]
    grep -q "systemctl start xo-server" "${XO_TEST_ROOT}/systemctl.log"
    # The install is the one that was there.
    [ -f "${XO_TEST_ROOT}/install/marker" ]
}

@test "rebuild: a failed clone and a failed restart is reported as stopped, with the backup" {
    run bash "$SCENARIO" rebuild clonestart
    [ "$status" -ne 0 ]
    [[ "$output" == *"The rebuild failed, and Xen Orchestra is stopped."* ]]
    [[ "$output" == *"--restore --backup-file xo-backup-"* ]]
}

@test "rebuild: a successful run prints no failure report" {
    run bash "$SCENARIO" rebuild none
    [ "$status" -eq 0 ]
    [[ "$output" == *"Rebuild completed successfully!"* ]]
    [[ "$output" != *"is stopped"* ]]
    [[ "$output" != *"--restore"* ]]
}

@test "the printed restore command restores exactly the backup it names" {
    run bash "$SCENARIO" update build
    local name
    name="$(basename "$(reported_backup)")"
    # A newer backup that --backup-file must not pick instead.
    cp -r "${XO_TEST_ROOT}/backups/${name}" "${XO_TEST_ROOT}/backups/xo-backup-29990101_000000"
    echo decoy > "${XO_TEST_ROOT}/backups/xo-backup-29990101_000000/marker"
    run bash "$SCENARIO" restore "$name"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Restoring from backup: ${name}"* ]]
    [ "$(cat "${XO_TEST_ROOT}/install/marker")" = "xo" ]
}

@test "the report names only a backup made in this run, not an older one" {
    mkdir -p "${XO_TEST_ROOT}/backups/xo-backup-20200101_000000"
    run bash "$SCENARIO" update flush
    [ "$status" -ne 0 ]
    [[ "$output" != *"xo-backup-20200101_000000"* ]]
    [[ "$output" != *"--restore"* ]]
}

@test "the report code reads nothing distro-specific" {
    # The failure message and the restore command must read the same on Debian,
    # Ubuntu, Rocky, AlmaLinux, CentOS Stream and Fedora. The integration job
    # runs the scenario in each of those images (test_install_smoke.bats); this
    # checks the code has no branch that could differ. (The facts block, in
    # print_failure_details, does print the distro name, on purpose.)
    run bash -c '_XO_SOURCE_ONLY=1 source "$1"; declare -f begin_service_downtime end_service_downtime report_failed_downtime on_script_error' _ "${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"report_failed_downtime"* ]]
    [[ "$output" != *OS_ID* ]]
    [[ "$output" != *OS_VERSION_ID* ]]
    [[ "$output" != *PKG* ]]
    [[ "$output" != *apt* ]]
    [[ "$output" != *dnf* ]]
    [[ "$output" != *yum* ]]
}

@test "the error trap leaves out 'start the service' while XO is stopped for an update" {
    run bash -c '_XO_SOURCE_ONLY=1 source "$1"; STOPPED_FOR=update; on_script_error 12 "false"' _ "${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
    [[ "$output" == *"Script failed at line 12: false."* ]]
    [[ "$output" != *"systemctl start"* ]]
}

@test "the error trap still gives the start hint when no update or rebuild stopped XO" {
    run bash -c '_XO_SOURCE_ONLY=1 source "$1"; on_script_error 12 "false"' _ "${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
    [[ "$output" == *"If the service was stopped, run: sudo systemctl start xo-server"* ]]
}
