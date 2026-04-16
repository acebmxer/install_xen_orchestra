#!/usr/bin/env bats
# Tests for version_satisfies() in install-xen-orchestra.sh

setup() {
    load '../helpers/mock_helpers'
    load_script
}

@test "major-only spec: 22.15.1 satisfies 22" {
    run version_satisfies "22.15.1" "22"
    [ "$status" -eq 0 ]
}

@test "major+minor spec: 22.15.1 satisfies 22.3" {
    run version_satisfies "22.15.1" "22.3"
    [ "$status" -eq 0 ]
}

@test "minor less than required: 22.1.0 does not satisfy 22.3" {
    run version_satisfies "22.1.0" "22.3"
    [ "$status" -eq 1 ]
}

@test "major mismatch: 20.20.1 does not satisfy 22" {
    run version_satisfies "20.20.1" "22"
    [ "$status" -eq 1 ]
}

@test "exact match: 22.3.1 satisfies 22.3.1" {
    run version_satisfies "22.3.1" "22.3.1"
    [ "$status" -eq 0 ]
}

@test "patch less than required: 22.3.0 does not satisfy 22.3.1" {
    run version_satisfies "22.3.0" "22.3.1"
    [ "$status" -eq 1 ]
}
