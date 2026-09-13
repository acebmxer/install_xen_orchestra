#!/usr/bin/env bats
# Tests for prune_xo_vm_snapshots() and the XO_API_TOKEN resolution fix in
# snapshot_xo_vm(), both in install-xen-orchestra.sh.

setup() {
    load '../helpers/mock_helpers'
    load_script

    SNAPSHOT_KEEP=3
    SNAPSHOT_RETENTION_DAYS=14
    HTTPS_PORT=443
    HTTP_PORT=80
}

# Builds a JSON array of vm-snapshots for the stubbed `curl -G` list call.
# Each arg is "id:name_label:snapshot_time".
_snap_json() {
    local out="[" first=true entry id name_label snap_time
    for entry in "$@"; do
        IFS=':' read -r id name_label snap_time <<< "$entry"
        [[ "$first" == true ]] || out+=","
        first=false
        out+="{\"id\":\"${id}\",\"name_label\":\"${name_label}\",\"snapshot_time\":${snap_time}}"
    done
    out+="]"
    printf '%s' "$out"
}

@test "keeps only SNAPSHOT_KEEP snapshots, deleting the oldest beyond that" {
    local now
    now=$(date +%s)
    # 5 of our own snapshots, all recent (age is not the reason for deletion here).
    local list
    list=$(_snap_json \
        "s1:xo-install-pre-update-1:$((now - 500))" \
        "s2:xo-install-pre-update-2:$((now - 400))" \
        "s3:xo-install-pre-update-3:$((now - 300))" \
        "s4:xo-install-pre-update-4:$((now - 200))" \
        "s5:xo-install-pre-update-5:$((now - 100))")

    DELETED_IDS_FILE=$(mktemp)
    # shellcheck disable=SC2317
    curl() {
        for a in "$@"; do
            if [[ "$a" == "-G" ]]; then
                echo "$list"
                return 0
            fi
        done
        for a in "$@"; do
            case "$a" in
                */rest/v0/vm-snapshots/*)
                    basename "$a" >> "$DELETED_IDS_FILE"
                    echo "204"
                    return 0
                    ;;
            esac
        done
        echo "000"
    }
    export -f curl

    prune_xo_vm_snapshots "vm-uuid" "tok" "https://localhost:443"

    # Newest 3 (s5, s4, s3) survive; the two oldest (s1, s2) are deleted.
    [ -f "$DELETED_IDS_FILE" ]
    run cat "$DELETED_IDS_FILE"
    [[ "$output" == *"s1"* ]]
    [[ "$output" == *"s2"* ]]
    [[ "$output" != *"s3"* ]]
    [[ "$output" != *"s4"* ]]
    [[ "$output" != *"s5"* ]]
    rm -f "$DELETED_IDS_FILE"
}

@test "deletes a snapshot older than SNAPSHOT_RETENTION_DAYS even when under SNAPSHOT_KEEP" {
    local now
    now=$(date +%s)
    SNAPSHOT_KEEP=10  # count alone would keep both
    local list
    list=$(_snap_json \
        "old1:xo-install-pre-rebuild-1:$((now - (20 * 86400)))" \
        "new1:xo-install-pre-rebuild-2:$((now - 100))")

    DELETED_IDS_FILE=$(mktemp)
    # shellcheck disable=SC2317
    curl() {
        for a in "$@"; do
            [[ "$a" == "-G" ]] && { echo "$list"; return 0; }
        done
        for a in "$@"; do
            case "$a" in
                */rest/v0/vm-snapshots/*)
                    basename "$a" >> "$DELETED_IDS_FILE"
                    echo "200"
                    return 0
                    ;;
            esac
        done
        echo "000"
    }
    export -f curl

    prune_xo_vm_snapshots "vm-uuid" "tok" "https://localhost:443"

    run cat "$DELETED_IDS_FILE"
    [[ "$output" == *"old1"* ]]
    [[ "$output" != *"new1"* ]]
    rm -f "$DELETED_IDS_FILE"
}

@test "never touches a snapshot outside this script's own xo-install- naming" {
    local now
    now=$(date +%s)
    SNAPSHOT_KEEP=1
    local list
    list=$(_snap_json \
        "manual1:Before risky change:$((now - 1000))" \
        "ours1:xo-install-pre-update-1:$((now - 500))" \
        "ours2:xo-install-pre-update-2:$((now - 100))")

    DELETED_IDS_FILE=$(mktemp)
    # shellcheck disable=SC2317
    curl() {
        for a in "$@"; do
            [[ "$a" == "-G" ]] && { echo "$list"; return 0; }
        done
        for a in "$@"; do
            case "$a" in
                */rest/v0/vm-snapshots/*)
                    basename "$a" >> "$DELETED_IDS_FILE"
                    echo "204"
                    return 0
                    ;;
            esac
        done
        echo "000"
    }
    export -f curl

    prune_xo_vm_snapshots "vm-uuid" "tok" "https://localhost:443"

    # Only ours1 (the older of our two, beyond SNAPSHOT_KEEP=1) is deleted.
    # The hand-made "manual1" snapshot is never a candidate at all.
    run cat "$DELETED_IDS_FILE"
    [[ "$output" == *"ours1"* ]]
    [[ "$output" != *"ours2"* ]]
    [[ "$output" != *"manual1"* ]]
    rm -f "$DELETED_IDS_FILE"
}

@test "an empty snapshot list prunes nothing and does not error" {
    # shellcheck disable=SC2317
    curl() {
        for a in "$@"; do
            [[ "$a" == "-G" ]] && { echo "[]"; return 0; }
        done
        echo "000"
    }
    export -f curl

    run prune_xo_vm_snapshots "vm-uuid" "tok" "https://localhost:443"
    [ "$status" -eq 0 ]
}

@test "a failed delete is warned about but does not stop pruning the rest" {
    local now
    now=$(date +%s)
    SNAPSHOT_KEEP=0
    local list
    list=$(_snap_json \
        "bad:xo-install-pre-update-1:$((now - 500))" \
        "good:xo-install-pre-update-2:$((now - 100))")

    DELETED_IDS_FILE=$(mktemp)
    # shellcheck disable=SC2317
    curl() {
        for a in "$@"; do
            [[ "$a" == "-G" ]] && { echo "$list"; return 0; }
        done
        for a in "$@"; do
            case "$a" in
                */rest/v0/vm-snapshots/bad)
                    echo "500"
                    return 0
                    ;;
                */rest/v0/vm-snapshots/*)
                    basename "$a" >> "$DELETED_IDS_FILE"
                    echo "204"
                    return 0
                    ;;
            esac
        done
        echo "000"
    }
    export -f curl

    run prune_xo_vm_snapshots "vm-uuid" "tok" "https://localhost:443"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Could not delete VM snapshot bad"* ]]
    run cat "$DELETED_IDS_FILE"
    [[ "$output" == *"good"* ]]
    rm -f "$DELETED_IDS_FILE"
}

@test "snapshot_xo_vm uses XO_API_TOKEN when only that is set" {
    # shellcheck disable=SC2317
    systemd-detect-virt() { echo "xen"; return 0; }
    export -f systemd-detect-virt
    # shellcheck disable=SC2317
    cat() {
        if [[ "$1" == "/sys/hypervisor/uuid" ]]; then echo "vm-uuid-123"; return 0; fi
        command cat "$@"
    }
    export -f cat

    XO_API_TOKEN="api-token-value"
    unset XO_TASK_CHECK_TOKEN

    SEEN_TOKEN_FILE=$(mktemp)
    # shellcheck disable=SC2317
    curl() {
        for a in "$@"; do
            [[ "$a" == authenticationToken=* ]] && echo "$a" >> "$SEEN_TOKEN_FILE"
        done
        for a in "$@"; do [[ "$a" == "-G" ]] && { echo "[]"; return 0; }; done
        echo "200"
    }
    export -f curl

    run snapshot_xo_vm "pre-update"
    [ "$status" -eq 0 ]
    run cat "$SEEN_TOKEN_FILE"
    [[ "$output" == *"api-token-value"* ]]
    rm -f "$SEEN_TOKEN_FILE"
}

@test "snapshot_xo_vm falls back to XO_TASK_CHECK_TOKEN when XO_API_TOKEN is unset" {
    # shellcheck disable=SC2317
    systemd-detect-virt() { echo "xen"; return 0; }
    export -f systemd-detect-virt
    # shellcheck disable=SC2317
    cat() {
        if [[ "$1" == "/sys/hypervisor/uuid" ]]; then echo "vm-uuid-123"; return 0; fi
        command cat "$@"
    }
    export -f cat

    unset XO_API_TOKEN
    XO_TASK_CHECK_TOKEN="legacy-token-value"

    SEEN_TOKEN_FILE=$(mktemp)
    # shellcheck disable=SC2317
    curl() {
        for a in "$@"; do
            [[ "$a" == authenticationToken=* ]] && echo "$a" >> "$SEEN_TOKEN_FILE"
        done
        for a in "$@"; do [[ "$a" == "-G" ]] && { echo "[]"; return 0; }; done
        echo "200"
    }
    export -f curl

    run snapshot_xo_vm "pre-update"
    [ "$status" -eq 0 ]
    run cat "$SEEN_TOKEN_FILE"
    [[ "$output" == *"legacy-token-value"* ]]
    rm -f "$SEEN_TOKEN_FILE"
}

@test "snapshot_xo_vm skips with no error when neither token is set" {
    # shellcheck disable=SC2317
    systemd-detect-virt() { echo "xen"; return 0; }
    export -f systemd-detect-virt
    # shellcheck disable=SC2317
    cat() {
        if [[ "$1" == "/sys/hypervisor/uuid" ]]; then echo "vm-uuid-123"; return 0; fi
        command cat "$@"
    }
    export -f cat

    unset XO_API_TOKEN
    unset XO_TASK_CHECK_TOKEN

    run snapshot_xo_vm "pre-update"
    [ "$status" -eq 0 ]
    [[ "$output" == *"No XO_API_TOKEN"* ]]
}
