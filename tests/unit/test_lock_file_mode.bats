#!/usr/bin/env bats
# acquire_lock used to chmod the lock file 666, so any local user could hold
# the lock or overwrite the PID in it (#115). It must now be owned by the
# invoking user with mode 600, including when an old 666 file already exists.

SCRIPT="${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"

setup() {
    LOCKDIR="$(mktemp -d)"
}

teardown() {
    rm -rf "$LOCKDIR"
}

# sudo is replaced by a plain pass-through so the case runs without root.
run_lock_case() {
    bash -c '_XO_SOURCE_ONLY=1 source "$1"; set +e; trap - ERR
        sudo() { "$@"; }
        XO_LOCKFILE="$2/xo-install.lock"
        '"$3"'
        acquire_lock
        stat -c "%a %u" "$XO_LOCKFILE"' _ "$SCRIPT" "$LOCKDIR" "$1"
}

@test "a new lock file is mode 600 and owned by the invoking user" {
    run run_lock_case ':'
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" = "600 $(id -u)" ]
}

@test "an existing world-writable lock file is tightened to 600" {
    run run_lock_case 'touch "$XO_LOCKFILE"; chmod 666 "$XO_LOCKFILE"'
    [ "$status" -eq 0 ]
    [ "${lines[-1]}" = "600 $(id -u)" ]
}
