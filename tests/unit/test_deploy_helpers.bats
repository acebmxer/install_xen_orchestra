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

@test "the guest is patched on first boot and keeps itself patched" {
    _deploy_drive_fixture

    deploy_build_config_drive

    local user_data="${DEPLOY_WORKDIR}/cidata/user-data"

    # The stock cloud image is only patched to its build date, so an install
    # that skips this exposes a web UI on a month-old package set.
    grep -q "^package_upgrade: true" "$user_data"
    grep -q "unattended-upgrades" "$user_data"

    # Written explicitly rather than left to the package's debconf default,
    # which differs between releases and can leave the timer switched off.
    grep -q "path: /etc/apt/apt.conf.d/20auto-upgrades" "$user_data"
    grep -q 'APT::Periodic::Unattended-Upgrade "1";' "$user_data"
}

@test "the generated user-data is valid YAML" {
    _deploy_drive_fixture
    DEPLOY_ADMIN_PASSWORD_HASH='$6$abcdefgh$0123456789'

    python3 -c "import yaml" 2>/dev/null || skip "python3 yaml not available"

    deploy_build_config_drive

    # write_files carries a literal block scalar, which is the easiest thing
    # here to indent wrongly; a broken document means cloud-init silently
    # configures nothing and the VM comes up unconfigured.
    run python3 -c "import sys,yaml; yaml.safe_load(open(sys.argv[1]))" \
        "${DEPLOY_WORKDIR}/cidata/user-data"
    [ "$status" -eq 0 ]
}

@test "the admin account still gets passwordless sudo for the install" {
    _deploy_drive_fixture

    deploy_build_config_drive

    # deploy_harden_guest_sudo revokes this after the install, but the
    # unattended run itself has no TTY to answer a password prompt, so the
    # config drive must still grant it.
    grep -q "NOPASSWD:ALL" "${DEPLOY_WORKDIR}/cidata/user-data"
}

# --- deploy_load_pubkey ---------------------------------------------------

@test "a public key is accepted from a file and from a literal" {
    command -v ssh-keygen >/dev/null || skip "ssh-keygen not available"
    ssh-keygen -t ed25519 -N "" -C "me@host" -f "${TMPDIR_TEST}/k" >/dev/null 2>&1

    run deploy_load_pubkey "${TMPDIR_TEST}/k.pub"
    [ "$status" -eq 0 ]
    [[ "$output" == "ssh-ed25519 "* ]]

    run deploy_load_pubkey "$(cat "${TMPDIR_TEST}/k.pub")"
    [ "$status" -eq 0 ]
    [[ "$output" == "ssh-ed25519 "* ]]
}

# The one that matters. ssh-keygen -l fingerprints a *private* key file quite
# happily, so a check built on that alone would accept one here — and the key
# goes straight into cloud-init's user-data, readable by anyone on the guest.
@test "a private key is rejected rather than embedded in user-data" {
    command -v ssh-keygen >/dev/null || skip "ssh-keygen not available"
    ssh-keygen -t ed25519 -N "" -C "me@host" -f "${TMPDIR_TEST}/k" >/dev/null 2>&1

    run deploy_load_pubkey "${TMPDIR_TEST}/k"
    [ "$status" -eq 1 ]
    [ -z "$output" ]
}

@test "malformed and truncated keys are rejected" {
    command -v ssh-keygen >/dev/null || skip "ssh-keygen not available"

    run deploy_load_pubkey "hello world"
    [ "$status" -eq 1 ]

    # Right key type, corrupt body — the type check alone would let this pass.
    run deploy_load_pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"
    [ "$status" -eq 1 ]

    run deploy_load_pubkey "/nonexistent/path.pub"
    [ "$status" -eq 1 ]
}

@test "a key saved with CRLF line endings still loads" {
    command -v ssh-keygen >/dev/null || skip "ssh-keygen not available"
    ssh-keygen -t ed25519 -N "" -C "me@host" -f "${TMPDIR_TEST}/k" >/dev/null 2>&1
    printf '%s\r\n' "$(cat "${TMPDIR_TEST}/k.pub")" > "${TMPDIR_TEST}/crlf.pub"

    run deploy_load_pubkey "${TMPDIR_TEST}/crlf.pub"
    [ "$status" -eq 0 ]
    [[ "$output" != *$'\r'* ]]
}

# --- the operator's key in user-data --------------------------------------

@test "a supplied public key is installed alongside the deployment key" {
    _deploy_drive_fixture
    ssh-keygen -t ed25519 -N "" -C "operator@laptop" -f "${TMPDIR_TEST}/mine" >/dev/null 2>&1
    DEPLOY_USER_PUBKEY=$(deploy_load_pubkey "${TMPDIR_TEST}/mine.pub")

    deploy_build_config_drive

    local user_data="${DEPLOY_WORKDIR}/cidata/user-data"
    grep -q "operator@laptop" "$user_data"
    grep -q "install-xen-orchestra deploy (temporary)" "$user_data"
    [ "$(grep -c '^      - ssh-' "$user_data")" -eq 2 ]
}

@test "without a supplied key only the deployment key is installed" {
    _deploy_drive_fixture
    DEPLOY_USER_PUBKEY=""

    deploy_build_config_drive

    local user_data="${DEPLOY_WORKDIR}/cidata/user-data"
    [ "$(grep -c '^      - ssh-' "$user_data")" -eq 1 ]
    grep -q "install-xen-orchestra deploy (temporary)" "$user_data"
}

# The deployment key is comment-tagged so deploy_revoke_deploy_key's fallback
# advice ("delete the line commented ...") actually finds something.
@test "the deployment key is tagged as temporary" {
    _deploy_drive_fixture

    deploy_build_config_drive

    grep -q "install-xen-orchestra deploy (temporary)" \
        "${DEPLOY_SSH_KEY}.pub"
}

# --- deploy_prompt_admin_password (now mandatory) -------------------------

@test "a non-interactive deploy without a password is refused" {
    NON_INTERACTIVE=true
    DEPLOY_ADMIN_USER=xo
    unset XO_DEPLOY_ADMIN_PASSWORD

    run deploy_prompt_admin_password
    [ "$status" -ne 0 ]
    [[ "$output" == *"XO_DEPLOY_ADMIN_PASSWORD"* ]]
}

@test "a non-interactive password below the minimum length is refused" {
    NON_INTERACTIVE=true
    DEPLOY_ADMIN_USER=xo
    XO_DEPLOY_ADMIN_PASSWORD="short"

    run deploy_prompt_admin_password
    [ "$status" -ne 0 ]
    [[ "$output" == *"${XO_DEPLOY_MIN_PASSWORD_LEN}"* ]]
}

@test "a non-interactive password is hashed, not stored in the clear" {
    command -v openssl >/dev/null || command -v mkpasswd >/dev/null \
        || skip "no password hashing tool available"
    NON_INTERACTIVE=true
    DEPLOY_ADMIN_USER=xo
    XO_DEPLOY_ADMIN_PASSWORD="correct horse battery staple"

    deploy_prompt_admin_password

    [[ "$DEPLOY_ADMIN_PASSWORD_HASH" == '$6$'* ]]
    [[ "$DEPLOY_ADMIN_PASSWORD_HASH" != *"correct horse"* ]]
}

# --- deploy_revoke_script -------------------------------------------------
#
# This program edits authorized_keys on the guest. Every case below is a way of
# getting it wrong that would either strand the operator or leave the key live.

_revoke() {
    # Runs the real remote program against a fixture HOME, feeding it the key
    # to remove on stdin exactly as deploy_revoke_deploy_key does.
    printf '%s\n' "$1" | HOME="$TMPDIR_TEST" sh -c "$(deploy_revoke_script)"
}

_auth_keys() { echo "${TMPDIR_TEST}/.ssh/authorized_keys"; }

_seed_keys() {
    mkdir -p "${TMPDIR_TEST}/.ssh"
    printf '%s\n' \
        "ssh-ed25519 AAAADEPLOY install-xen-orchestra deploy (temporary)" \
        "ssh-ed25519 AAAAMINE operator@laptop" \
        "ssh-rsa AAAAOTHER someone@else" > "$(_auth_keys)"
    chmod 644 "$(_auth_keys)"
}

@test "revoking removes the deployment key and nothing else" {
    _seed_keys

    run _revoke "ssh-ed25519 AAAADEPLOY install-xen-orchestra deploy (temporary)"
    [ "$status" -eq 0 ]

    [ "$(wc -l < "$(_auth_keys)")" -eq 2 ]
    ! grep -q "AAAADEPLOY" "$(_auth_keys)"
    grep -q "operator@laptop" "$(_auth_keys)"
    grep -q "someone@else" "$(_auth_keys)"
}

@test "revoking tightens authorized_keys permissions" {
    _seed_keys

    _revoke "ssh-ed25519 AAAADEPLOY install-xen-orchestra deploy (temporary)"

    [ "$(stat -c '%a' "$(_auth_keys)")" = "600" ]
}

# An empty pattern makes grep -vxF match nothing and pass every line through —
# but a naive implementation could just as easily match *everything* and hand
# back an empty file, locking the operator out of the VM they just built.
@test "an empty key aborts instead of emptying authorized_keys" {
    _seed_keys

    run _revoke ""
    [ "$status" -ne 0 ]

    [ "$(wc -l < "$(_auth_keys)")" -eq 3 ]
}

@test "revoking twice is harmless" {
    _seed_keys
    local key="ssh-ed25519 AAAADEPLOY install-xen-orchestra deploy (temporary)"

    _revoke "$key"
    run _revoke "$key"
    [ "$status" -eq 0 ]

    [ "$(wc -l < "$(_auth_keys)")" -eq 2 ]
}

@test "revoking succeeds when there is no authorized_keys file" {
    mkdir -p "${TMPDIR_TEST}/.ssh"

    run _revoke "ssh-ed25519 AAAADEPLOY install-xen-orchestra deploy (temporary)"
    [ "$status" -eq 0 ]
}

# A partial match must not take a key with it: "AAAAMINE" is a substring of no
# other line here, but a grep without -x would still be wrong on a key whose
# text is a prefix of another.
@test "matching is exact, not substring" {
    mkdir -p "${TMPDIR_TEST}/.ssh"
    printf '%s\n' \
        "ssh-ed25519 AAAAKEY deploy" \
        "ssh-ed25519 AAAAKEY deploy extra" > "$(_auth_keys)"

    _revoke "ssh-ed25519 AAAAKEY deploy"

    [ "$(wc -l < "$(_auth_keys)")" -eq 1 ]
    grep -q "deploy extra" "$(_auth_keys)"
}

@test "deploy_revoke_deploy_key is a no-op without SSH options or a key" {
    DEPLOY_SSH_OPTS=()
    DEPLOY_PUBKEY="ssh-ed25519 AAAADEPLOY deploy"
    run deploy_revoke_deploy_key
    [ "$status" -eq 0 ]

    DEPLOY_SSH_OPTS=(-o BatchMode=yes)
    DEPLOY_PUBKEY=""
    run deploy_revoke_deploy_key
    [ "$status" -eq 0 ]
}

# --- deploy_harden_guest_sudo --------------------------------------------

@test "sudo hardening is skipped, with a warning, for a key-only account" {
    DEPLOY_SSH_OPTS=(-o BatchMode=yes)
    DEPLOY_ADMIN_USER=xo
    DEPLOY_IP=192.168.1.50
    DEPLOY_ADMIN_PASSWORD_HASH=""
    DEPLOY_SUDO_HARDENED="unset"

    # Requiring a password from an account that has none is a lockout, not
    # hardening, so this must not even try to connect. A stub that fails loudly
    # catches a regression that reorders the guard below the ssh call.
    ssh() { echo "ssh must not be called" >&2; return 1; }

    # Output goes to a file rather than through `run` or a command
    # substitution: both would run the function in a subshell, and the
    # assertion below is about the variable it sets in the caller.
    local out="${TMPDIR_TEST}/harden.out"
    local status=0
    deploy_harden_guest_sudo > "$out" 2>&1 || status=$?
    local output
    output=$(cat "$out")

    [ "$status" -eq 0 ]
    [ "$DEPLOY_SUDO_HARDENED" = "false" ]
    [[ "$output" != *"ssh must not be called"* ]]
    [[ "$output" == *"ALL=(ALL:ALL) ALL"* ]]
    [[ "$output" == *"passwd"* ]]
}

@test "sudo hardening is a no-op when no SSH options were established" {
    DEPLOY_SSH_OPTS=()
    DEPLOY_ADMIN_PASSWORD_HASH='$6$abcdefgh$0123456789'

    run deploy_harden_guest_sudo
    [ "$status" -eq 0 ]
}

@test "the cloud-init cache scrub is a no-op without SSH options" {
    DEPLOY_SSH_OPTS=()

    run deploy_scrub_guest_cloudinit_cache
    [ "$status" -eq 0 ]
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

# --- input validation -----------------------------------------------------
#
# The prompts pair a shape regex with these validators. The regex alone accepts
# values that look like addresses and ports but are not, and every one of them
# is only rejected after the VM exists — by cloud-init producing an unreachable
# guest, or by the installer inside it refusing the port.

@test "is_ipv4 accepts real addresses and rejects out-of-range octets" {
    is_ipv4 192.168.1.50
    is_ipv4 0.0.0.0
    is_ipv4 255.255.255.255

    ! is_ipv4 999.999.999.999
    ! is_ipv4 192.168.1.256
    ! is_ipv4 192.168.1
    ! is_ipv4 192.168.1.1.1
    ! is_ipv4 ""
    ! is_ipv4 "not-an-ip"
}

# Leading zeros must not be read as octal: 010 is 10, not 8, and 08 is not an
# error.
@test "is_ipv4 treats zero-padded octets as decimal" {
    is_ipv4 010.008.001.050
    ! is_ipv4 010.008.001.300
}

@test "is_port enforces the full 1-65535 range" {
    is_port 1
    is_port 80
    is_port 65535

    ! is_port 0
    ! is_port 70000
    ! is_port 65536
    ! is_port -1
    ! is_port ""
    ! is_port abc
}

# --- xml_escape -----------------------------------------------------------

@test "xml_escape escapes the characters that break an XML-RPC body" {
    [ "$(xml_escape 'a&b')" = 'a&amp;b' ]
    [ "$(xml_escape 'a<b>c')" = 'a&lt;b&gt;c' ]
    [ "$(xml_escape 'plain')" = 'plain' ]

    # & must be escaped first, or the ampersands introduced by the later
    # substitutions get escaped a second time.
    [ "$(xml_escape '<&>')" = '&lt;&amp;&gt;' ]
}

# --- deploy_set_config_key ------------------------------------------------

@test "deploy_set_config_key appends a key the base config never had" {
    local f="${TMPDIR_TEST}/cfg"
    printf 'HTTPS_PORT=443\n' > "$f"

    deploy_set_config_key "$f" HTTP_PORT 8080

    grep -qx "HTTP_PORT=8080" "$f"
    grep -qx "HTTPS_PORT=443" "$f"
}

@test "deploy_set_config_key replaces an existing key in place" {
    local f="${TMPDIR_TEST}/cfg"
    printf '# comment\nHTTP_PORT=80\nGIT_BRANCH=master\n' > "$f"

    deploy_set_config_key "$f" HTTP_PORT 8080

    [ "$(grep -c '^HTTP_PORT=' "$f")" -eq 1 ]
    grep -qx "HTTP_PORT=8080" "$f"
    grep -qx "# comment" "$f"
}

# A base config that omits a prompted key is legal — load_config defaults it —
# so the generated config must still carry the answer, or the guest installs on
# the default while the summary shows what was typed.
@test "generated config carries prompted keys the base config omits" {
    local base="${TMPDIR_TEST}/base.cfg"
    printf 'INSTALL_DIR=/opt/xo\n' > "$base"
    DEPLOY_CONFIG_BASE="$base"
    DEPLOY_HTTP_PORT=8080
    DEPLOY_HTTPS_PORT=8443
    DEPLOY_GIT_BRANCH=stable

    deploy_build_xo_config

    grep -qx "HTTP_PORT=8080" "$DEPLOY_XO_CONFIG"
    grep -qx "HTTPS_PORT=8443" "$DEPLOY_XO_CONFIG"
    grep -qx "GIT_BRANCH=stable" "$DEPLOY_XO_CONFIG"
    grep -qx "INSTALL_DIR=/opt/xo" "$DEPLOY_XO_CONFIG"
}

# --- deploy_guest_clone_url -----------------------------------------------
#
# The VM gets neither the operator's SSH key nor their credentials, so an
# origin that works on the workstation is not necessarily one the guest can
# clone — and one that carries a token must not be copied into user-data.

@test "an SSH origin becomes an HTTPS URL the guest can reach" {
    [ "$(deploy_guest_clone_url 'git@github.com:acebmxer/install_xen_orchestra.git')" \
        = "https://github.com/acebmxer/install_xen_orchestra.git" ]
    [ "$(deploy_guest_clone_url 'ssh://git@github.com/acebmxer/repo.git')" \
        = "https://github.com/acebmxer/repo.git" ]
    [ "$(deploy_guest_clone_url 'ssh://git@git.example.com:2222/team/repo.git')" \
        = "https://git.example.com/team/repo.git" ]
}

@test "credentials embedded in an HTTPS origin are stripped" {
    [ "$(deploy_guest_clone_url 'https://user:ghp_secret@github.com/o/repo.git')" \
        = "https://github.com/o/repo.git" ]
    [ "$(deploy_guest_clone_url 'https://token@github.com/o/repo.git')" \
        = "https://github.com/o/repo.git" ]
}

@test "a plain HTTPS origin is passed through untouched" {
    local url="https://github.com/acebmxer/install_xen_orchestra.git"
    [ "$(deploy_guest_clone_url "$url")" = "$url" ]

    # A port on an HTTPS origin is part of the address, not an SSH artefact.
    [ "$(deploy_guest_clone_url 'https://git.example.com:8443/o/repo.git')" \
        = "https://git.example.com:8443/o/repo.git" ]
}

# --- is_safe_url ----------------------------------------------------------
#
# The image URL is interpolated into a single-quoted argument in a shell on the
# pool master.

@test "is_safe_url rejects anything that could escape a remote single quote" {
    is_safe_url "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.raw"
    is_safe_url "http://mirror.local/img.raw?token=abc&v=1"

    ! is_safe_url "https://host/img.raw'; rm -rf /; echo '"
    ! is_safe_url "https://host/img raw"
    ! is_safe_url "file:///etc/passwd"
    ! is_safe_url ""
}
