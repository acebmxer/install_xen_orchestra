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

@test "a chosen base config is used instead of the sample" {
    # What a user gets when they point the deploy at their own xo-config.cfg:
    # the prompted keys still win, everything else comes from their file.
    # Not named xo-config.cfg: that is what deploy_build_xo_config writes
    # into the same work dir.
    local base="${TMPDIR_TEST}/local-xo-config.cfg"
    cp "$SAMPLE_CONFIG" "$base"
    sed -i -e 's|^INSTALL_DIR=.*|INSTALL_DIR=/srv/xen-orchestra|' \
           -e 's|^SERVICE_USER=.*|SERVICE_USER=xo-service|' \
           -e 's|^HTTP_PORT=.*|HTTP_PORT=8080|' "$base"

    DEPLOY_CONFIG_BASE="$base"
    DEPLOY_HTTP_PORT=80
    DEPLOY_HTTPS_PORT=443
    DEPLOY_GIT_BRANCH=master

    deploy_build_xo_config

    grep -qx "INSTALL_DIR=/srv/xen-orchestra" "$DEPLOY_XO_CONFIG"
    grep -qx "SERVICE_USER=xo-service" "$DEPLOY_XO_CONFIG"
    # The prompt is the authority for the three keys it collects.
    grep -qx "HTTP_PORT=80" "$DEPLOY_XO_CONFIG"
}

@test "a missing base config is an error, not a silent fallback" {
    DEPLOY_CONFIG_BASE="${TMPDIR_TEST}/does-not-exist.cfg"
    DEPLOY_HTTP_PORT=80
    DEPLOY_HTTPS_PORT=443
    DEPLOY_GIT_BRANCH=master

    run deploy_build_xo_config
    [ "$status" -ne 0 ]
    [[ "$output" == *"Base config not found"* ]]
}

@test "deploy_config_value reads keys without sourcing the file" {
    local cfg="${TMPDIR_TEST}/some.cfg"
    cat > "$cfg" <<'EOF'
# HTTP_PORT=9999
HTTP_PORT=8080
GIT_BRANCH=stable   # trailing comment
PREFERRED_EDITOR="vim"
EOF

    [ "$(deploy_config_value "$cfg" HTTP_PORT)" = "8080" ]
    [ "$(deploy_config_value "$cfg" GIT_BRANCH)" = "stable" ]
    [ "$(deploy_config_value "$cfg" PREFERRED_EDITOR)" = "vim" ]
    [ -z "$(deploy_config_value "$cfg" NOT_A_KEY)" ]
    [ -z "$(deploy_config_value "${TMPDIR_TEST}/missing.cfg" HTTP_PORT)" ]
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

# Set the variables deploy_build_config_drive reads, so each test below only
# has to override the one thing it is about.
_deploy_drive_fixture() {
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
}

@test "no password leaves the account locked and key-only" {
    _deploy_drive_fixture
    DEPLOY_ADMIN_PASSWORD_HASH=""
    DEPLOY_ADMIN_SSH_PWAUTH=false

    deploy_build_config_drive

    local user_data="${DEPLOY_WORKDIR}/cidata/user-data"
    grep -q "lock_passwd: true" "$user_data"
    ! grep -q "hashed_passwd" "$user_data"
    grep -q "ssh_pwauth: false" "$user_data"
}

@test "a password hash is embedded and the account unlocked" {
    _deploy_drive_fixture
    DEPLOY_ADMIN_PASSWORD_HASH='$6$abcdefgh$0123456789'
    DEPLOY_ADMIN_SSH_PWAUTH=false

    deploy_build_config_drive

    local user_data="${DEPLOY_WORKDIR}/cidata/user-data"
    grep -q "lock_passwd: false" "$user_data"
    grep -qF "hashed_passwd: '\$6\$abcdefgh\$0123456789'" "$user_data"

    # A password must not silently open up SSH...
    grep -q "ssh_pwauth: false" "$user_data"
    # ...and must not expire on the first console login.
    grep -q "expire: false" "$user_data"
}

@test "password SSH logins are enabled only when asked for" {
    _deploy_drive_fixture
    DEPLOY_ADMIN_PASSWORD_HASH='$6$abcdefgh$0123456789'
    DEPLOY_ADMIN_SSH_PWAUTH=true

    deploy_build_config_drive

    grep -q "ssh_pwauth: true" "${DEPLOY_WORKDIR}/cidata/user-data"
}

@test "the repo is cloned into the chosen directory" {
    _deploy_drive_fixture
    DEPLOY_REPO_DIR=/home/xo/install_xen_orchestra

    deploy_build_config_drive

    local user_data="${DEPLOY_WORKDIR}/cidata/user-data"
    grep -q 'git, clone, "https://example.invalid/repo.git", "/home/xo/install_xen_orchestra"' "$user_data"
    grep -q 'chown, -R, "xo:xo", "/home/xo/install_xen_orchestra"' "$user_data"
    ! grep -q "/opt/install_xen_orchestra" "$user_data"
}

@test "deploy_hash_password produces a SHA-512 crypt string" {
    command -v openssl >/dev/null || command -v mkpasswd >/dev/null \
        || skip "no password hashing tool available"

    run deploy_hash_password "correct horse battery staple"
    [ "$status" -eq 0 ]
    [[ "$output" == '$6$'* ]]

    # The same password twice must not give the same hash, or the salt is
    # not being applied.
    run deploy_hash_password "correct horse battery staple"
    local second="$output"
    run deploy_hash_password "correct horse battery staple"
    [ "$output" != "$second" ]
}
