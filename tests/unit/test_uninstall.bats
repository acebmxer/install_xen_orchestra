#!/usr/bin/env bats
# --uninstall (cleanup_xo) stops and disables xo-server before removing it.

setup() {
    load '../helpers/mock_helpers'
    load_script

    DRY_RUN=false
    SERVICE_USER=root
    INSTALL_DIR="$BATS_TEST_TMPDIR/xen-orchestra"
    SSL_CERT_DIR="$BATS_TEST_TMPDIR/ssl"
    BACKUP_DIR="$BATS_TEST_TMPDIR/backups"
    CALLS="$BATS_TEST_TMPDIR/calls.log"
    : > "$CALLS"

    check_required_commands() { :; }
    check_not_root() { :; }
    check_sudo() { :; }
    check_systemctl() { :; }
    load_config() { :; }
    # Yes to the uninstall itself, no to the optional extras.
    confirm_or_skip() { [[ "$1" == Proceed* ]]; }

    # sudo runs systemctl (stubbed below) and only records anything else, so
    # nothing on the test machine is removed.
    sudo() {
        if [[ "$1" == systemctl ]]; then "$@"; else echo "sudo $*" >> "$CALLS"; fi
    }
    # An installed, enabled xo-server unit, as both the old
    # (list-unit-files) and new (cat) checks would see it.
    systemctl() {
        echo "systemctl $*" >> "$CALLS"
        case "$1" in
            cat) echo "[Unit]"; return 0 ;;
            list-unit-files) echo "xo-server.service enabled enabled"; return 0 ;;
        esac
        return 0
    }
}

@test "uninstall stops and disables an installed xo-server" {
    run cleanup_xo
    [ "$status" -eq 0 ]
    [[ "$output" == *"Stopping xo-server service"* ]]
    grep -q '^systemctl stop xo-server$' "$CALLS"
    grep -q '^systemctl disable xo-server$' "$CALLS"
}

@test "uninstall skips stop/disable when there is no xo-server unit" {
    systemctl() {
        echo "systemctl $*" >> "$CALLS"
        [[ "$1" == cat ]] && return 1
        return 0
    }
    run cleanup_xo
    [ "$status" -eq 0 ]
    # Positive control: the unit check itself ran.
    grep -q '^systemctl cat xo-server.service$' "$CALLS"
    run grep -q '^systemctl stop xo-server$' "$CALLS"
    [ "$status" -eq 1 ]
}
