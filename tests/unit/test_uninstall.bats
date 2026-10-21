#!/usr/bin/env bats
# --uninstall (cleanup_xo) stops and disables xo-server before removing it,
# and its "purge Redis data" empties the data dirs without breaking Redis.

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

# purge_redis_data with real files in throwaway data dirs. sudo runs
# everything (systemctl is still the stub), so `find -delete` really runs.
purge_setup() {
    sudo() { "$@"; }
    REDIS_DIR="$BATS_TEST_TMPDIR/redis"
    VALKEY_DIR="$BATS_TEST_TMPDIR/valkey"
    mkdir -p "$VALKEY_DIR/appendonlydir"
    echo data > "$VALKEY_DIR/dump.rdb"
    echo aof > "$VALKEY_DIR/appendonlydir/appendonly.aof"
    # Only valkey is installed; it stops and starts cleanly unless STOP_RC
    # says otherwise.
    STOP_RC=0
    systemctl() {
        echo "systemctl $*" >> "$CALLS"
        case "$1 $2" in
            "cat valkey.service") return 0 ;;
            cat\ *) return 1 ;;
            "stop valkey") return "$STOP_RC" ;;
        esac
        return 0
    }
    find() { echo "find $*" >> "$CALLS"; command find "$@"; }
}

@test "purge: stops the valkey service, empties its data dir, keeps the dir, starts it again" {
    purge_setup
    run purge_redis_data "$REDIS_DIR" "$VALKEY_DIR"
    [ "$status" -eq 0 ]
    [ -d "$VALKEY_DIR" ]
    [ -z "$(ls -A "$VALKEY_DIR")" ]
    # The missing redis dir is skipped, not created.
    [ ! -e "$REDIS_DIR" ]
    # Order: stop, then delete, then start.
    run grep -n -e '^systemctl stop valkey$' -e '^find ' -e '^systemctl start valkey$' "$CALLS"
    [ "${#lines[@]}" -eq 3 ]
    [[ "${lines[0]}" == *"stop valkey" ]]
    [[ "${lines[1]}" == *"find $VALKEY_DIR -mindepth 1 -delete" ]]
    [[ "${lines[2]}" == *"start valkey" ]]
}

@test "purge: data is kept when the service can't be stopped" {
    purge_setup
    STOP_RC=1
    run purge_redis_data "$REDIS_DIR" "$VALKEY_DIR"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Redis data was NOT purged"* ]]
    [ -f "$VALKEY_DIR/dump.rdb" ]
}

@test "uninstall: 'purge Redis data' purges both data dirs" {
    confirm_or_skip() { [[ "$1" == Proceed* || "$1" == *"purge Redis data"* ]]; }
    purge_redis_data() { echo "purge $*" >> "$CALLS"; }
    run cleanup_xo
    [ "$status" -eq 0 ]
    grep -q '^purge /var/lib/redis /var/lib/valkey$' "$CALLS"
}
