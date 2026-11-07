#!/usr/bin/env bats
# Tests for NODE_VERSION=lts: resolve_node_lts_major(), resolve_node_version()
# and the validate_config() check, in install-xen-orchestra.sh.
# curl is replaced by a function that prints a canned copy of nodejs.org's
# index.json (newest first, one release per line), so nothing touches the net.

setup() {
    load '../helpers/mock_helpers'
    load_script

    INDEX_FILE="${BATS_TEST_TMPDIR}/index.json"
    cat > "$INDEX_FILE" <<'JSON'
[
{"version":"v27.0.0-alpha.0.0.0","date":"2026-10-29","npm":"12.1.0","lts":false,"security":false},
{"version":"v26.13.0","date":"2026-10-28","npm":"11.20.0","lts":"Lithium","security":false},
{"version":"v26.12.1","date":"2026-10-21","npm":"11.19.1","lts":false,"security":true},
{"version":"v24.22.2","date":"2026-10-28","npm":"11.19.1","lts":"Krypton","security":false}
]
JSON
    export INDEX_FILE
    curl() { cat "$INDEX_FILE"; }
    export -f curl
}

@test "resolve_node_lts_major picks the newest LTS line, not a newer non-LTS one" {
    run resolve_node_lts_major
    [ "$status" -eq 0 ]
    [ "$output" = "26" ]
}

@test "resolve_node_lts_major fails when nodejs.org cannot be read" {
    curl() { return 22; }
    export -f curl
    run resolve_node_lts_major
    [ "$status" -eq 1 ]
}

@test "resolve_node_lts_major fails when the index has no LTS release" {
    echo '[{"version":"v27.0.0","lts":false}]' > "$INDEX_FILE"
    run resolve_node_lts_major
    [ "$status" -eq 1 ]
}

@test "resolve_node_version turns lts into the newest LTS major" {
    NODE_VERSION=lts
    resolve_node_version >/dev/null
    [ "$NODE_VERSION" = "26" ]
}

@test "resolve_node_version accepts LTS in any case" {
    NODE_VERSION=LTS
    resolve_node_version >/dev/null
    [ "$NODE_VERSION" = "26" ]
}

@test "resolve_node_version leaves a numeric version alone" {
    NODE_VERSION=24.15
    resolve_node_version
    [ "$NODE_VERSION" = "24.15" ]
}

@test "resolve_node_version fails with a clear message when nodejs.org is unreachable" {
    curl() { return 22; }
    export -f curl
    NODE_VERSION=lts
    run resolve_node_version
    [ "$status" -eq 1 ]
    [[ "$output" == *"NODE_VERSION=lts"* ]]
}

@test "validate_config accepts NODE_VERSION=lts" {
    HTTP_PORT=80 HTTPS_PORT=443 INSTALL_DIR=/opt/xen-orchestra BACKUP_KEEP=5
    SERVICE_USER=xo-service ENCRYPT_REDIS_CREDENTIALS=false TURBO_CACHE_ENABLED=true
    NODE_VERSION=lts
    run validate_config
    [ "$status" -eq 0 ]
}
