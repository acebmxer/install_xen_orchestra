#!/usr/bin/env bats
# Tests for the pure helpers behind --deploy in install-xen-orchestra.sh.
#
# The parts that talk to a pool master over SSH are not covered here — they
# need a real XAPI host. What is covered is everything that can silently
# produce a wrong-but-plausible result: netmask conversion, the option picker,
# and the generated cloud-init / xo-config content.

setup() {
    load '../helpers/mock_helpers'
    load_script

    TMPDIR_TEST=$(mktemp -d)
    DEPLOY_WORKDIR="$TMPDIR_TEST"
    SAMPLE_CONFIG="${BATS_TEST_DIRNAME}/../../sample-xo-config.cfg"
}

teardown() {
    rm -rf "$TMPDIR_TEST"
}

# --- netmask_to_prefix ----------------------------------------------------

@test "common netmasks convert to the right prefix" {
    [ "$(netmask_to_prefix 255.255.255.0)" = "24" ]
    [ "$(netmask_to_prefix 255.255.0.0)" = "16" ]
    [ "$(netmask_to_prefix 255.0.0.0)" = "8" ]
    [ "$(netmask_to_prefix 0.0.0.0)" = "0" ]
}

@test "non-byte-aligned netmasks convert correctly" {
    [ "$(netmask_to_prefix 255.255.255.128)" = "25" ]
    [ "$(netmask_to_prefix 255.255.255.252)" = "30" ]
    [ "$(netmask_to_prefix 255.255.254.0)" = "23" ]
    [ "$(netmask_to_prefix 255.255.255.255)" = "32" ]
}

@test "octets that are not valid mask bytes are rejected" {
    run netmask_to_prefix 255.99.0.0
    [ "$status" -eq 1 ]
    [ -z "$output" ]
}

# A discontiguous mask has a plausible-looking bit count, so a converter that
# only sums octets returns /16 here and puts the guest on the wrong subnet.
@test "discontiguous netmasks are rejected rather than summed" {
    run netmask_to_prefix 255.0.255.0
    [ "$status" -eq 1 ]
    [ -z "$output" ]

    run netmask_to_prefix 0.255.0.0
    [ "$status" -eq 1 ]

    run netmask_to_prefix 255.255.0.128
    [ "$status" -eq 1 ]
}

# --- deploy_choose --------------------------------------------------------

@test "a single option is selected without prompting" {
    run deploy_choose "Pick one" "the-uuid|Some label"
    [ "$status" -eq 0 ]
    [[ "$output" == *"only option"* ]]
}

@test "deploy_choose sets the value, not the label" {
    deploy_choose "Pick one" "the-uuid|Some label"
    [ "$DEPLOY_CHOICE" = "the-uuid" ]
}

@test "deploy_choose fails when given no options" {
    run deploy_choose "Pick one"
    [ "$status" -ne 0 ]
}

# --- deploy_build_xo_config ----------------------------------------------

@test "generated config applies the deploy answers over the sample" {
    DEPLOY_HTTP_PORT=8080
    DEPLOY_HTTPS_PORT=8443
    DEPLOY_GIT_BRANCH=stable

    deploy_build_xo_config

    [ -f "$DEPLOY_XO_CONFIG" ]
    grep -qx "HTTP_PORT=8080" "$DEPLOY_XO_CONFIG"
    grep -qx "HTTPS_PORT=8443" "$DEPLOY_XO_CONFIG"
    grep -qx "GIT_BRANCH=stable" "$DEPLOY_XO_CONFIG"
}

@test "generated config keeps the sample's other defaults" {
    DEPLOY_HTTP_PORT=80
    DEPLOY_HTTPS_PORT=443
    DEPLOY_GIT_BRANCH=master

    deploy_build_xo_config

    # SERVICE_USER is not prompted for at deploy time, so it must come through
    # from the sample unchanged — which is what puts the VM on root.
    grep -qx "SERVICE_USER=root" "$DEPLOY_XO_CONFIG"
    grep -qx "CONFIG_VERSION=${LATEST_CONFIG_VERSION}" "$DEPLOY_XO_CONFIG"
}

@test "each key is written exactly once" {
    DEPLOY_HTTP_PORT=80
    DEPLOY_HTTPS_PORT=443
    DEPLOY_GIT_BRANCH=master

    deploy_build_xo_config

    [ "$(grep -c '^HTTP_PORT=' "$DEPLOY_XO_CONFIG")" -eq 1 ]
    [ "$(grep -c '^HTTPS_PORT=' "$DEPLOY_XO_CONFIG")" -eq 1 ]
    [ "$(grep -c '^GIT_BRANCH=' "$DEPLOY_XO_CONFIG")" -eq 1 ]
}

# --- deploy_build_config_drive -------------------------------------------

@test "cloud-init user-data and network-config are well formed" {
    command -v ssh-keygen >/dev/null || skip "ssh-keygen not available"
    command -v genisoimage >/dev/null || command -v xorriso >/dev/null \
        || skip "no ISO writer available"

    DEPLOY_VM_NAME=test-vm
    DEPLOY_HOSTNAME=test-vm
    DEPLOY_ADMIN_USER=xo
    DEPLOY_IP=192.168.1.50
    DEPLOY_PREFIX=24
    DEPLOY_GATEWAY=192.168.1.1
    DEPLOY_DNS=1.1.1.1
    DEPLOY_REPO_URL="https://example.invalid/repo.git"

    deploy_build_config_drive

    local dir="${DEPLOY_WORKDIR}/cidata"
    grep -q "^#cloud-config" "${dir}/user-data"
    grep -q "name: xo" "${dir}/user-data"
    grep -q "NOPASSWD:ALL" "${dir}/user-data"
    grep -q "ssh_pwauth: false" "${dir}/user-data"
    grep -q "example.invalid/repo.git" "${dir}/user-data"

    # The generated public key must actually be embedded, not a placeholder.
    grep -q "ssh-ed25519 " "${dir}/user-data"

    grep -q "192.168.1.50/24" "${dir}/network-config"
    grep -q "via: 192.168.1.1" "${dir}/network-config"
    grep -q "local-hostname: test-vm" "${dir}/meta-data"

    # The ISO must carry the cidata label or cloud-init's NoCloud datasource
    # will never look at it.
    [ -f "$DEPLOY_CIDATA_ISO" ]
    if command -v blkid >/dev/null; then
        blkid -o value -s LABEL "$DEPLOY_CIDATA_ISO" | grep -qi cidata
    fi
}

@test "the private key is written with owner-only permissions" {
    command -v ssh-keygen >/dev/null || skip "ssh-keygen not available"
    command -v genisoimage >/dev/null || command -v xorriso >/dev/null \
        || skip "no ISO writer available"

    DEPLOY_VM_NAME=test-vm
    DEPLOY_HOSTNAME=test-vm
    DEPLOY_ADMIN_USER=xo
    DEPLOY_IP=192.168.1.50
    DEPLOY_PREFIX=24
    DEPLOY_GATEWAY=192.168.1.1
    DEPLOY_DNS=1.1.1.1
    DEPLOY_REPO_URL="https://example.invalid/repo.git"

    deploy_build_config_drive

    [ "$(stat -c '%a' "$DEPLOY_SSH_KEY")" = "600" ]
}
