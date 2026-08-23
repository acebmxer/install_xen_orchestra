#!/usr/bin/env bats
# Tests for load_config() and migrate_config() in install-xen-orchestra.sh

setup() {
    load '../helpers/mock_helpers'
    load_script

    TMPDIR_TEST=$(mktemp -d)
    CONFIG_FILE="${TMPDIR_TEST}/xo-config.cfg"
    SAMPLE_CONFIG="${BATS_TEST_DIRNAME}/../../sample-xo-config.cfg"
}

teardown() {
    rm -rf "$TMPDIR_TEST"
}

@test "load_config creates config from sample when missing" {
    # CONFIG_FILE does not exist yet
    run load_config
    [ "$status" -eq 0 ]
    [ -f "$CONFIG_FILE" ]
}

@test "config already at the latest version passes migrate_config unchanged" {
    # Write a minimal valid config already stamped at the latest version
    cat > "$CONFIG_FILE" <<EOF
CONFIG_VERSION=${LATEST_CONFIG_VERSION}
HTTP_PORT=80
HTTPS_PORT=443
INSTALL_DIR=/opt/xen-orchestra
BACKUP_KEEP=5
NODE_VERSION=22
SERVICE_USER=xo-service
EOF
    CONFIG_VERSION=${LATEST_CONFIG_VERSION}
    run migrate_config "$CONFIG_FILE"
    [ "$status" -eq 0 ]
    # CONFIG_VERSION should still appear exactly once, not duplicated
    count=$(grep -c "^CONFIG_VERSION=" "$CONFIG_FILE")
    [ "$count" -eq 1 ]
}

@test "a v2 config gains SSL_CERT_DAYS on migration" {
    cat > "$CONFIG_FILE" <<'EOF'
CONFIG_VERSION=2
HTTP_PORT=80
HTTPS_PORT=443
INSTALL_DIR=/opt/xen-orchestra
BACKUP_KEEP=5
NODE_VERSION=22
SERVICE_USER=xo-service
EOF
    CONFIG_VERSION=2
    run migrate_config "$CONFIG_FILE"
    [ "$status" -eq 0 ]

    grep -q "^SSL_CERT_DAYS=825" "$CONFIG_FILE"
    grep -q "^CONFIG_VERSION=${LATEST_CONFIG_VERSION}" "$CONFIG_FILE"
    [ "$(grep -c "^SSL_CERT_DAYS=" "$CONFIG_FILE")" -eq 1 ]
}

@test "migration does not overwrite an SSL_CERT_DAYS the user already set" {
    cat > "$CONFIG_FILE" <<'EOF'
CONFIG_VERSION=2
HTTP_PORT=80
HTTPS_PORT=443
INSTALL_DIR=/opt/xen-orchestra
BACKUP_KEEP=5
NODE_VERSION=22
SERVICE_USER=xo-service
SSL_CERT_DAYS=90
EOF
    CONFIG_VERSION=2
    run migrate_config "$CONFIG_FILE"
    [ "$status" -eq 0 ]

    grep -q "^SSL_CERT_DAYS=90" "$CONFIG_FILE"
    [ "$(grep -c "^SSL_CERT_DAYS=" "$CONFIG_FILE")" -eq 1 ]
}

@test "legacy config without CONFIG_VERSION is migrated to the latest schema version" {
    # Write a config with no CONFIG_VERSION (legacy)
    cat > "$CONFIG_FILE" <<'EOF'
HTTP_PORT=80
HTTPS_PORT=443
INSTALL_DIR=/opt/xen-orchestra
BACKUP_KEEP=5
NODE_VERSION=22
SERVICE_USER=xo-service
EOF
    CONFIG_VERSION=""
    run migrate_config "$CONFIG_FILE"
    [ "$status" -eq 0 ]
    grep -q "^CONFIG_VERSION=${LATEST_CONFIG_VERSION}" "$CONFIG_FILE"
    # CONFIG_VERSION should appear exactly once
    count=$(grep -c "^CONFIG_VERSION=" "$CONFIG_FILE")
    [ "$count" -eq 1 ]
}
