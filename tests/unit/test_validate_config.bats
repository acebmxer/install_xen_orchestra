#!/usr/bin/env bats
# Tests for validate_config() in install-xen-orchestra.sh

setup() {
    load '../helpers/mock_helpers'
    load_script

    # Set valid defaults before each test
    HTTP_PORT=80
    HTTPS_PORT=443
    INSTALL_DIR=/opt/xen-orchestra
    BACKUP_KEEP=5
    NODE_VERSION=22
    SERVICE_USER=xo-service
}

@test "valid config passes validation" {
    run validate_config
    [ "$status" -eq 0 ]
}

@test "non-numeric HTTP_PORT fails with HTTP_PORT in output" {
    HTTP_PORT="abc"
    run validate_config
    [ "$status" -eq 1 ]
    [[ "$output" == *"HTTP_PORT"* ]]
}

@test "HTTP_PORT out of range fails" {
    HTTP_PORT=99999
    run validate_config
    [ "$status" -eq 1 ]
}

@test "relative INSTALL_DIR fails" {
    INSTALL_DIR="relative/path"
    run validate_config
    [ "$status" -eq 1 ]
}

@test "BACKUP_KEEP=0 fails" {
    BACKUP_KEEP=0
    run validate_config
    [ "$status" -eq 1 ]
}

@test "invalid SERVICE_USER characters fail" {
    SERVICE_USER="root!@#"
    run validate_config
    [ "$status" -eq 1 ]
}

@test "non-numeric NODE_VERSION fails" {
    NODE_VERSION="latest"
    run validate_config
    [ "$status" -eq 1 ]
}
