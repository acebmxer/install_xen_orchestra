#!/usr/bin/env bats
# Tests for get_previous_service_user() and cleanup_stale_service_user()
# in install-xen-orchestra.sh — the SERVICE_USER=root migration path.

setup() {
    load '../helpers/mock_helpers'
    load_script

    TMPDIR_TEST=$(mktemp -d)
    INSTALL_DIR="${TMPDIR_TEST}/xen-orchestra"
    mkdir -p "$INSTALL_DIR"

    # cleanup_stale_service_user shells out to `rm`/`udevadm` via run_cmd sudo,
    # and sudo is stubbed to true by mock_helpers, so no real files are touched.
    DRY_RUN=false
}

teardown() {
    rm -rf "$TMPDIR_TEST"
}

# --- get_previous_service_user -------------------------------------------

@test "previous service user is read from the systemd unit" {
    # get_previous_service_user reads the real unit path, so this test only
    # runs where that file is absent — otherwise it would read the host's.
    [ ! -f /etc/systemd/system/xo-server.service ] || skip "host has a real xo-server unit"

    # With no unit present it falls back to the install directory's owner,
    # which under test is whoever runs bats.
    run get_previous_service_user
    [ "$status" -eq 0 ]
    [ "$output" = "$(stat -c '%U' "$INSTALL_DIR")" ]
}

@test "previous service user is empty when neither unit nor install dir exist" {
    [ ! -f /etc/systemd/system/xo-server.service ] || skip "host has a real xo-server unit"

    INSTALL_DIR="${TMPDIR_TEST}/does-not-exist"
    run get_previous_service_user
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

# --- cleanup_stale_service_user ------------------------------------------

@test "cleanup is a no-op when SERVICE_USER is not root" {
    SERVICE_USER=xo-service
    run cleanup_stale_service_user "some-old-user"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "cleanup is a no-op when the previous user was already root" {
    SERVICE_USER=root
    run cleanup_stale_service_user "root"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "cleanup is a no-op when no previous user could be determined" {
    SERVICE_USER=root
    run cleanup_stale_service_user ""
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "cleanup reports a still-present previous account without deleting it" {
    SERVICE_USER=root
    # 'nobody' exists on every supported distro and is never the service user.
    run cleanup_stale_service_user "nobody"
    [ "$status" -eq 0 ]
    [[ "$output" == *"nobody"* ]]
    [[ "$output" == *"userdel"* ]]
    # The account must still exist — cleanup only reports, never deletes.
    id nobody
}

@test "cleanup succeeds when the previous account no longer exists" {
    SERVICE_USER=root
    run cleanup_stale_service_user "xo-service-that-never-existed"
    [ "$status" -eq 0 ]
    # Nothing to report about a missing account.
    [[ "$output" != *"userdel"* ]]
}
