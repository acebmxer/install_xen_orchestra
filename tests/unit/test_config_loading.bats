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

# --- Template build method and the XO API token ----------------------------
#
# The token key was renamed when --build-templates became a second consumer of
# it. The rename must be invisible to anyone whose config predates it, which is
# the case these first tests pin down: a config holding only the old key still
# authenticates, and nothing about it needs editing.

@test "an existing XO_TASK_CHECK_TOKEN is used when XO_API_TOKEN is unset" {
    cat > "$CONFIG_FILE" << 'CFG'
INSTALL_DIR=/opt/xen-orchestra
XO_TASK_CHECK_TOKEN=old-token-value
CONFIG_VERSION=4
CFG
    run load_config
    [ "$status" -eq 0 ]

    load_config
    [ "$XO_API_TOKEN" = "old-token-value" ]
}

@test "XO_API_TOKEN wins when both token keys are set" {
    cat > "$CONFIG_FILE" << 'CFG'
INSTALL_DIR=/opt/xen-orchestra
XO_TASK_CHECK_TOKEN=old-token-value
XO_API_TOKEN=new-token-value
CONFIG_VERSION=4
CFG
    load_config
    [ "$XO_API_TOKEN" = "new-token-value" ]
}

@test "no token in the config leaves XO_API_TOKEN empty rather than unset" {
    cat > "$CONFIG_FILE" << 'CFG'
INSTALL_DIR=/opt/xen-orchestra
CONFIG_VERSION=4
CFG
    load_config
    # Empty, not unset: the build path reads it under `set -u`.
    [ -z "$XO_API_TOKEN" ]
}

@test "TEMPLATE_BUILD_METHOD defaults to auto" {
    cat > "$CONFIG_FILE" << 'CFG'
INSTALL_DIR=/opt/xen-orchestra
CONFIG_VERSION=4
CFG
    load_config
    [ "$TEMPLATE_BUILD_METHOD" = "auto" ]
}

@test "an invalid TEMPLATE_BUILD_METHOD is rejected" {
    cat > "$CONFIG_FILE" << 'CFG'
INSTALL_DIR=/opt/xen-orchestra
TEMPLATE_BUILD_METHOD=sideways
CONFIG_VERSION=4
CFG
    run load_config
    [ "$status" -ne 0 ]
    [[ "$output" == *"TEMPLATE_BUILD_METHOD"* ]]
}

@test "each valid TEMPLATE_BUILD_METHOD is accepted" {
    local method
    for method in auto api ssh; do
        cat > "$CONFIG_FILE" << CFG
INSTALL_DIR=/opt/xen-orchestra
TEMPLATE_BUILD_METHOD=${method}
CONFIG_VERSION=4
CFG
        run load_config
        [ "$status" -eq 0 ]
    done
}

@test "an XO_URL without a scheme is rejected" {
    cat > "$CONFIG_FILE" << 'CFG'
INSTALL_DIR=/opt/xen-orchestra
XO_URL=xo.example.com
CONFIG_VERSION=4
CFG
    run load_config
    [ "$status" -ne 0 ]
    [[ "$output" == *"XO_URL"* ]]
}

@test "the v4 migration adds the template keys without touching an existing token" {
    cat > "$CONFIG_FILE" << 'CFG'
INSTALL_DIR=/opt/xen-orchestra
XO_TASK_CHECK_TOKEN=keep-me
CONFIG_VERSION=3
CFG
    run load_config
    [ "$status" -eq 0 ]

    # The operator's token is left exactly as it was ...
    grep -qx "XO_TASK_CHECK_TOKEN=keep-me" "$CONFIG_FILE"
    # ... and the new keys are documented, commented out so that nothing
    # starts behaving differently on the strength of a migration alone.
    grep -q "^#TEMPLATE_BUILD_METHOD=auto" "$CONFIG_FILE"
    grep -q "^#XO_URL=" "$CONFIG_FILE"
    grep -q "^#XO_API_TOKEN=" "$CONFIG_FILE"
    grep -qx "CONFIG_VERSION=4" "$CONFIG_FILE"
}

@test "the v4 migration does not duplicate keys that are already present" {
    cat > "$CONFIG_FILE" << 'CFG'
INSTALL_DIR=/opt/xen-orchestra
TEMPLATE_BUILD_METHOD=ssh
XO_URL=https://xo.example.com
XO_API_TOKEN=already-here
CONFIG_VERSION=3
CFG
    load_config
    [ "$(grep -c '^TEMPLATE_BUILD_METHOD=' "$CONFIG_FILE")" -eq 1 ]
    [ "$(grep -c '^XO_URL=' "$CONFIG_FILE")" -eq 1 ]
    [ "$(grep -c '^XO_API_TOKEN=' "$CONFIG_FILE")" -eq 1 ]
}

@test "tpl_api_base_url prefers XO_URL and strips a trailing slash" {
    XO_URL="https://xo.example.com/"
    HTTPS_PORT=443
    [ "$(tpl_api_base_url)" = "https://xo.example.com" ]
}

@test "tpl_api_base_url falls back to localhost on XO's own port" {
    XO_URL=""
    HTTPS_PORT=8443
    [ "$(tpl_api_base_url)" = "https://localhost:8443" ]
}

@test "the API path is skipped when no token is configured" {
    XO_API_TOKEN=""
    CONFIG_FILE="${TMPDIR_TEST}/xo-config.cfg"
    run tpl_api_check_auth
    [ "$status" -ne 0 ]
}

@test "TEMPLATE_BUILD_METHOD=ssh never contacts the API" {
    TEMPLATE_BUILD_METHOD=ssh
    # Any API call would go through curl; make it fail loudly if reached.
    curl() { echo "API CONTACTED" >&2; return 1; }
    export -f curl 2>/dev/null || true

    run tpl_select_build_method
    [ "$status" -eq 0 ]
    [[ "$output" != *"API CONTACTED"* ]]
    [[ "$output" == *"SSH"* ]]
}

@test "TEMPLATE_BUILD_METHOD=api fails loudly instead of falling back" {
    TEMPLATE_BUILD_METHOD=api
    XO_API_TOKEN=""

    run tpl_select_build_method
    [ "$status" -ne 0 ]
    [[ "$output" == *"unavailable"* ]]
}

@test "auto falls back to SSH and says why" {
    TEMPLATE_BUILD_METHOD=auto
    XO_API_TOKEN=""

    run tpl_select_build_method
    [ "$status" -eq 0 ]
    [[ "$output" == *"SSH"* ]]
    [[ "$output" == *"no XO_API_TOKEN"* ]]
}
