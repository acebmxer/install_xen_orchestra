#!/usr/bin/env bats
# The heap size set with --adjust-memory (--max-old-space-size on the
# xo-server unit's ExecStart line) survives create_systemd_service, which
# --update, --rebuild, --reconfigure and --restore all call.

setup() {
    load '../helpers/mock_helpers'
    load_script

    DRY_RUN=false
    SERVICE_USER=root
    DEBUG_MODE=false
    INSTALL_DIR=/opt/xen-orchestra
    UNIT_OUT="$BATS_TEST_TMPDIR/xo-server.service.written"

    # Capture what create_systemd_service writes with `sudo tee <unit>`
    # instead of touching /etc; everything else sudo runs is a no-op.
    # shellcheck disable=SC2317
    sudo() {
        if [[ "$1" == tee ]]; then cat > "$UNIT_OUT"; fi
        return 0
    }
}

@test "xo_service_heap_limit reads the value from ExecStart" {
    local f="$BATS_TEST_TMPDIR/unit"
    printf '[Service]\nExecStart=/usr/local/bin/node --max-old-space-size=6000 /opt/xen-orchestra/packages/xo-server/dist/cli.mjs\n' > "$f"
    run xo_service_heap_limit "$f"
    [ "$status" -eq 0 ]
    [ "$output" = "6000" ]
}

@test "xo_service_heap_limit prints nothing without the flag or the file" {
    local f="$BATS_TEST_TMPDIR/unit"
    printf '[Service]\nExecStart=/usr/local/bin/node /opt/xen-orchestra/packages/xo-server/dist/cli.mjs\n' > "$f"
    run xo_service_heap_limit "$f"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
    run xo_service_heap_limit "$BATS_TEST_TMPDIR/missing"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "rewriting the unit keeps the --adjust-memory heap size" {
    xo_service_heap_limit() { echo 6000; }
    run create_systemd_service
    [ "$status" -eq 0 ]
    [[ "$output" == *"Keeping the 6000 MB heap size"* ]]
    grep -qE '^ExecStart=[^ ]* --max-old-space-size=6000 /opt/xen-orchestra/packages/xo-server/dist/cli.mjs$' "$UNIT_OUT"
}

@test "rewriting a unit with no heap size adds none" {
    xo_service_heap_limit() { :; }
    run create_systemd_service
    [ "$status" -eq 0 ]
    # Positive control: the unit was written.
    grep -q '^ExecStart=' "$UNIT_OUT"
    run grep -q 'max-old-space-size' "$UNIT_OUT"
    [ "$status" -eq 1 ]
}
