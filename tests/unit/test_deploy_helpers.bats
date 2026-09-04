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

@test "the generated config is a verbatim copy of the base" {
    deploy_build_xo_config

    [ -f "$DEPLOY_XO_CONFIG" ]
    # Nothing is rewritten on the way through. Rewriting three keys and
    # carrying the other twenty untouched was an arbitrary split.
    diff -q "$SAMPLE_CONFIG" "$DEPLOY_XO_CONFIG"
}

@test "every setting in a chosen base config reaches the VM unchanged" {
    # Not named xo-config.cfg: that is what deploy_build_xo_config writes
    # into the same work dir.
    local base="${TMPDIR_TEST}/local-xo-config.cfg"
    cp "$SAMPLE_CONFIG" "$base"
    sed -i -e 's|^INSTALL_DIR=.*|INSTALL_DIR=/srv/xen-orchestra|' \
           -e 's|^SERVICE_USER=.*|SERVICE_USER=xo-service|' \
           -e 's|^NODE_VERSION=.*|NODE_VERSION=22|' \
           -e 's|^HTTP_PORT=.*|HTTP_PORT=8080|' \
           -e 's|^GIT_BRANCH=.*|GIT_BRANCH=stable|' "$base"

    DEPLOY_CONFIG_BASE="$base"

    deploy_build_xo_config

    # Ports and branch are settings like any other. They used to be overwritten
    # from prompts, which meant a config that said 8080 deployed as 80.
    grep -qx "HTTP_PORT=8080" "$DEPLOY_XO_CONFIG"
    grep -qx "GIT_BRANCH=stable" "$DEPLOY_XO_CONFIG"
    grep -qx "INSTALL_DIR=/srv/xen-orchestra" "$DEPLOY_XO_CONFIG"
    grep -qx "SERVICE_USER=xo-service" "$DEPLOY_XO_CONFIG"
    grep -qx "NODE_VERSION=22" "$DEPLOY_XO_CONFIG"
    diff -q "$base" "$DEPLOY_XO_CONFIG"
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

# --- image import ---------------------------------------------------------
#
# These run against a stubbed dom0_exec that records the commands rather than
# executing them, so the shape of what gets sent to the pool master is pinned.
# Every assertion here corresponds to a way a 3 GB transfer has actually gone
# wrong: a truncated image imported as if it were whole, an hour-long hang, or
# a retry that silently duplicated bytes.

_import_stub() {
    CMDLOG="${TMPDIR_TEST}/cmds"
    : > "$CMDLOG"
    STAGED_SIZE="${STAGED_SIZE:-3221225472}"
    DEPLOY_SESSION="OpaqueRef:test"
    HOST_USERNAME=root
    POOL_MASTER_IP=10.0.0.1
    FREE_MB="${FREE_MB:-999999}"
    dom0_exec() {
        printf '%s\n' "$*" >> "$CMDLOG"
        case "$*" in
            *content-length*) echo "3221225472" ;;
            # Both default to empty, which is the "origin publishes no sums"
            # path -- so tests written before checksumming existed are
            # unaffected by it.
            *SHA512SUMS*)     printf '%s' "${SUMS_BODY:-}" ;;
            *sha512sum*)      printf '%s' "${ACTUAL_SHA:-}" ;;
            *"df -BM"*)       echo "$FREE_MB" ;;
            *"stat -c %s"*)   echo "$STAGED_SIZE" ;;
            # XAPI's import endpoint takes an opaque ref, so every import
            # resolves the VDI's uuid to one first.
            *"param-name=_ref"*) echo "OpaqueRef:00000000-1111-2222-3333-444444444444" ;;
            *"--progress-bar"*) [[ -z "${DOWNLOAD_FAILS:-}" ]] || return 1 ;;
        esac
        return 0
    }
}

@test "staging is the default path, not the fallback" {
    _import_stub

    deploy_import_vdi_from_url "vdi-1" "https://example.invalid/img.raw"

    # Staging is the only path that can resume, retry and size-check, so it is
    # what a normal deploy should use. Streaming must not be attempted at all
    # when there is room to stage.
    grep -q -- "--progress-bar" "$CMDLOG"
    ! grep -q -- "bash -s --" "$CMDLOG"
}

@test "streaming is used only when there is no room to stage" {
    _import_stub
    FREE_MB=10

    deploy_import_vdi_from_url "vdi-1" "https://example.invalid/img.raw"

    grep -q -- "bash -s --" "$CMDLOG"
}

@test "a staged download that fails for any other reason does not fall through" {
    _import_stub
    DOWNLOAD_FAILS=1

    run deploy_import_vdi_from_url "vdi-1" "https://example.invalid/img.raw"
    [ "$status" -ne 0 ]

    # Retrying by streaming after the download already exhausted its retries
    # just spends minutes reaching the same failure.
    ! grep -q -- "bash -s --" "$CMDLOG"
}

# --- deploy_stream_script -------------------------------------------------

_stream_stub_curl() {
    mkdir -p "${TMPDIR_TEST}/bin"
    cat > "${TMPDIR_TEST}/bin/curl" <<'STUB'
#!/bin/sh
case "$*" in
  *-T\ -*)
      # The upload: drain what arrives, then block the way curl does while it
      # waits for a response XAPI will never send.
      cat >/dev/null
      echo "upload-still-running" >> "$STREAM_MARK"
      sleep 60
      exit 0 ;;
  *)
      # The download: emit a little, then die like the TLS error did.
      echo "partial"
      [ -n "$DL_FAILS" ] && exit 56
      exit 0 ;;
esac
STUB
    chmod +x "${TMPDIR_TEST}/bin/curl"
}

# The bug this pins: with a plain `curl | curl`, a download that dies leaves the
# upload waiting on a response until --max-time 3600. An hour of apparent hang,
# which in practice means the operator interrupts the deploy.
@test "a dead download kills the upload instead of waiting it out" {
    _stream_stub_curl
    export STREAM_MARK="${TMPDIR_TEST}/mark"
    : > "$STREAM_MARK"

    local start_ts end_ts status=0
    start_ts=$(date +%s)
    DL_FAILS=1 PATH="${TMPDIR_TEST}/bin:$PATH" \
        bash -s -- "https://example.invalid/img.raw" 100 "https://localhost/import" \
        <<< "$(deploy_stream_script)" >/dev/null 2>&1 || status=$?
    end_ts=$(date +%s)

    [ "$status" -ne 0 ]
    # The stub upload sleeps 60s. Returning promptly proves it was killed
    # rather than waited on.
    [ $(( end_ts - start_ts )) -lt 20 ]
}

@test "the stream script runs under pipefail and guards against stalls" {
    run deploy_stream_script

    [[ "$output" == *"set -o pipefail"* ]]
    [ "$(grep -c -- "--speed-time 60" <<< "$output")" -eq 2 ]
    [ "$(grep -c -- "--speed-limit 1024" <<< "$output")" -eq 2 ]
}

# curl retries by re-issuing from byte 0. Piped into a PUT with a fixed
# Content-Length, those bytes land *after* the ones already sent: a corrupt
# image that imports without complaint. Resuming is the staged path's job.
@test "the stream script never uses --retry" {
    run deploy_stream_script

    [[ "$output" != *"--retry"* ]]
}

@test "the staged download resumes and retries" {
    _import_stub

    deploy_import_vdi_staged "vdi-1" "https://example.invalid/img.raw"

    local line
    line=$(grep -- "--progress-bar" "$CMDLOG")
    [[ "$line" == *"-C -"* ]]
    [[ "$line" == *"--retry 5"* ]]
    [[ "$line" == *"--retry-all-errors"* ]]
}

@test "a truncated staged download is refused, not imported" {
    _import_stub
    # curl exits 0 but the file on disk is short of what the server advertised.
    STAGED_SIZE=1000

    run deploy_import_vdi_staged "vdi-1" "https://example.invalid/img.raw"
    [ "$status" -eq 1 ]
    [[ "$output" == *"truncated"* ]]

    # It must not have attempted the import with a short file.
    ! grep -q "import_raw_vdi" "$CMDLOG"
}

@test "a staged download matching the advertised size is imported" {
    _import_stub
    STAGED_SIZE=3221225472

    run deploy_import_vdi_staged "vdi-1" "https://example.invalid/img.raw"
    [ "$status" -eq 0 ]
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
@test "a trimmed-down base config is copied as-is, not padded out" {
    local base="${TMPDIR_TEST}/base.cfg"
    printf 'INSTALL_DIR=/opt/xo\n' > "$base"
    DEPLOY_CONFIG_BASE="$base"

    deploy_build_xo_config

    grep -qx "INSTALL_DIR=/opt/xo" "$DEPLOY_XO_CONFIG"
    # Keys the file leaves out are the VM's own load_config to default, the
    # same as any other install. Nothing is injected here.
    [ "$(wc -l < "$DEPLOY_XO_CONFIG")" -eq 1 ]
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

# --- security regressions -------------------------------------------------
#
# Each test below reproduces a defect found in a security review of the
# --deploy path. They are written to fail against the code as it was, so a
# refactor that quietly reintroduces one is caught rather than silently
# accepted.

# The free-space probe feeds the pool master's reply into (( )), which expands
# an array subscript before evaluating it. An answer of PATH[$(...)] therefore
# runs on the *workstation*, making a hostile or impersonated host a local code
# execution vector.
#
# The payload names PATH rather than an unset variable on purpose: `set -u`
# aborts on the textbook x[$(...)] form, which makes that version of this test
# pass against vulnerable code.
@test "a hostile free-space reply is not executed as arithmetic" {
    local marker="${TMPDIR_TEST}/pwned"

    # `stat` answers with a plausible size so the staged-file check does not
    # short-circuit the function before the free-space probe is reached; the
    # payload under test is the df reply. Both replies go through the same
    # regex gate, so the marker proves neither was evaluated.
    dom0_exec() {
        case "$*" in
            *content-length*) echo "" ;;
            *stat*)           echo "3221225472" ;;
            *df*)             echo "PATH[\$(touch ${marker})]" ;;
            *)                echo "" ;;
        esac
    }

    deploy_import_vdi_staged "fake-vdi" "https://example.com/image.raw" >/dev/null 2>&1 || true

    [ ! -e "$marker" ]
}

@test "a hostile staged-size reply is not executed as arithmetic" {
    # Same class of vulnerability as the free-space probe: the staged file's
    # size comes from the pool master and is compared numerically, so it must
    # pass the same string gate before reaching (( )).
    local marker="${TMPDIR_TEST}/pwned-stat"

    dom0_exec() {
        case "$*" in
            *content-length*) echo "" ;;
            *df*)             echo "999999" ;;
            *stat*)           echo "PATH[\$(touch ${marker})]" ;;
            *)                echo "" ;;
        esac
    }

    # `run` rather than a bare call: the staged-size guard correctly returns
    # non-zero for this reply (it is not a number), and the script's ERR trap
    # turns a bare failing call into an aborted test before the assertion runs.
    run deploy_import_vdi_staged "fake-vdi" "https://example.com/image.raw"

    [ ! -e "$marker" ]
}

# A pinned fingerprint is an explicit request for enforcement. Every path that
# cannot complete the check used to return success, so a probe an attacker
# could stall meant the host password was sent unverified.
@test "an unverifiable pinned fingerprint refuses to continue" {
    local stub="${TMPDIR_TEST}/bin"
    mkdir -p "$stub"
    printf '#!/bin/sh\nexit 1\n' > "${stub}/ssh-keyscan"
    printf '#!/bin/sh\nexit 1\n' > "${stub}/ssh-keygen"
    chmod +x "${stub}/ssh-keyscan" "${stub}/ssh-keygen"

    POOL_MASTER_IP="192.0.2.10"
    NON_INTERACTIVE=true
    XO_DEPLOY_POOL_FINGERPRINT="SHA256:definitely-not-the-real-key"

    PATH="${stub}:${PATH}" run deploy_verify_host_key
    [ "$status" -ne 0 ]
}

# ...but an operator who set no pin keeps the previous behaviour: warn about
# the unknown key and carry on. Turning that into a hard failure would break
# every existing deploy.
@test "an unverifiable host key without a pin still continues" {
    local stub="${TMPDIR_TEST}/bin"
    mkdir -p "$stub"
    printf '#!/bin/sh\nexit 1\n' > "${stub}/ssh-keyscan"
    printf '#!/bin/sh\nexit 1\n' > "${stub}/ssh-keygen"
    chmod +x "${stub}/ssh-keyscan" "${stub}/ssh-keygen"

    POOL_MASTER_IP="192.0.2.10"
    NON_INTERACTIVE=true
    unset XO_DEPLOY_POOL_FINGERPRINT

    PATH="${stub}:${PATH}" run deploy_verify_host_key
    [ "$status" -eq 0 ]
}

# Fingerprinting a key and then connecting under accept-new verifies one
# transaction and trusts another.
@test "dom0_exec binds to the pinned host key once one is recorded" {
    DEPLOY_POOL_KNOWN_HOSTS="${TMPDIR_TEST}/pool_known_hosts"
    echo "192.0.2.10 ssh-ed25519 AAAAFAKE" > "$DEPLOY_POOL_KNOWN_HOSTS"

    ssh() { printf '%s\n' "$*"; }
    DEPLOY_AUTH_MODE="prompt"
    HOST_USERNAME=root
    POOL_MASTER_IP=192.0.2.10
    DEPLOY_SSH_CTL="${TMPDIR_TEST}/ctl"

    run dom0_exec true
    [[ "$output" == *"StrictHostKeyChecking=yes"* ]]
    [[ "$output" == *"UserKnownHostsFile=${DEPLOY_POOL_KNOWN_HOSTS}"* ]]
    [[ "$output" != *"accept-new"* ]]
}

# The hash is a credential. The script masks secrets under XO_DEBUG=1
# everywhere else; these two functions were missing the guard.
@test "the admin password hash is not printed by xtrace" {
    DEPLOY_ADMIN_PASSWORD_HASH='$6$SALT$SECRETHASHVALUE'
    DEPLOY_SSH_OPTS=(-o BatchMode=yes)
    DEPLOY_ADMIN_USER=xo
    DEPLOY_IP=192.0.2.9
    ssh() { return 1; }

    # xtrace has to be captured in *this* shell: a `bash -c` subshell does not
    # have the function defined, so it would exit 127 and the assertion below
    # would pass without ever running the code under test. BASH_XTRACEFD sends
    # the trace to a file instead of stderr so it can be searched.
    exec 9>"${TMPDIR_TEST}/xtrace"
    BASH_XTRACEFD=9
    set -x
    deploy_harden_guest_sudo >/dev/null 2>&1 || true
    set +x
    exec 9>&-

    [ -s "${TMPDIR_TEST}/xtrace" ]
    ! grep -q "SECRETHASHVALUE" "${TMPDIR_TEST}/xtrace"
}

# A grep that fails for a real reason (no space for the temp file) used to be
# swallowed, and the empty result written back over authorized_keys — taking
# the operator's own key with it.
@test "a grep failure leaves authorized_keys untouched" {
    [ "$(id -u)" -ne 0 ] || skip "root bypasses the permission this test relies on"

    _seed_keys
    local before
    before=$(cat "$(_auth_keys)")

    # Write-only is the exact shape of the bug: `[ -f ]` still passes and the
    # final write would succeed, but grep cannot read the file and exits 2. The
    # old `|| true` swallowed that and wrote the empty result back.
    #
    # Pointing TMPDIR somewhere unwritable does not work here -- `mktemp` fails
    # first and the program exits before reaching the grep, so the test passes
    # against the unfixed code without exercising anything.
    chmod 200 "$(_auth_keys)"
    run _revoke "ssh-ed25519 AAAADEPLOY install-xen-orchestra deploy (temporary)"
    chmod 600 "$(_auth_keys)"

    [ "$status" -ne 0 ]
    [ "$(cat "$(_auth_keys)")" = "$before" ]
}

# A control, not a regression: removing the only key in the file is a
# legitimate empty result. This passes before and after the fix, and exists so
# that distinguishing grep's exit codes does not turn the legitimate case into
# an error.
@test "revoking the only key leaves an empty file, not a failure" {
    mkdir -p "${TMPDIR_TEST}/.ssh"
    printf '%s\n' "ssh-ed25519 AAAADEPLOY install-xen-orchestra deploy (temporary)" > "$(_auth_keys)"

    run _revoke "ssh-ed25519 AAAADEPLOY install-xen-orchestra deploy (temporary)"
    [ "$status" -eq 0 ]
    [ ! -s "$(_auth_keys)" ]
}

# OpenSSH refuses DSA outright, so accepting one installs a key that never works.
#
# Asserted against the allowlist rather than end-to-end: ssh-keygen rejects a
# malformed DSA blob on its own, so feeding one to deploy_load_pubkey passes
# whether or not ssh-dss is still listed. A real DSA key cannot be generated to
# test with either -- current OpenSSH answers "unknown key type dsa", which is
# precisely why the entry had to go.
@test "DSA is not in the accepted public key type list" {
    local src="${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
    local hits
    hits=$(grep -v '^[[:space:]]*#' "$src" | grep -c 'ssh-dss' || true)
    [ "$hits" -eq 0 ]
}

# The FIFO used by the streaming import lives in dom0's world-writable /tmp.
@test "the stream script creates its FIFO inside a private directory" {
    # Comment lines are stripped first: the program explains *why* it avoids
    # `mktemp -u`, and a naive substring search matches that prose and fails on
    # correct code.
    local code
    code=$(deploy_stream_script | grep -v '^[[:space:]]*#')

    [[ "$code" != *"mktemp -u"* ]]
    [[ "$code" == *"mktemp -d"* ]]
}

# The rendered cloud-config carries hashed_passwd just as the raw user-data does.
@test "the cloud-init scrub covers the rendered cloud-config" {
    local src="${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
    grep -q 'instance/cloud-config.txt' "$src"
    grep -q 'instances/\*/cloud-config.txt' "$src"
}

# An argument is readable in `ps` for the life of the call; an environment
# variable of another user's process is not.
@test "the pool master password is never passed to sshpass as an argument" {
    # Comments stripped for the same reason as the FIFO test above: the note
    # explaining the choice names `sshpass -p` in prose.
    local src="${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
    local hits
    hits=$(grep -v '^[[:space:]]*#' "$src" | grep -c 'sshpass -p' || true)
    [ "$hits" -eq 0 ]
}

# --- image checksum verification ------------------------------------------
#
# The size check catches a download that was cut short. It cannot catch one
# that arrived complete from the wrong place, because a substituted image has a
# consistent Content-Length. This image becomes the appliance holding the
# pool's root credentials, so a wrong one matters.

_sha_a() { printf 'a%.0s' $(seq 128); }
_sha_b() { printf 'b%.0s' $(seq 128); }

@test "an image that does not match the published checksum is refused" {
    _import_stub
    SUMS_BODY="$(_sha_a)  img.raw"
    ACTUAL_SHA="$(_sha_b)"

    run deploy_import_vdi_staged "vdi-1" "https://example.invalid/img.raw"

    [ "$status" -eq 1 ]
    [[ "$output" == *"does not match"* ]]
    # Nothing may reach the disk.
    ! grep -q "import_raw_vdi" "$CMDLOG"
}

@test "an image matching the published checksum is imported" {
    _import_stub
    SUMS_BODY="$(_sha_a)  img.raw"
    ACTUAL_SHA="$(_sha_a)"

    run deploy_import_vdi_staged "vdi-1" "https://example.invalid/img.raw"

    [ "$status" -eq 0 ]
    grep -q "import_raw_vdi" "$CMDLOG"
}

# coreutils writes a '*' before the filename in binary mode; the entry has to
# be found either way.
@test "a binary-mode SHA512SUMS entry is matched" {
    _import_stub
    SUMS_BODY="$(_sha_a) *img.raw"
    ACTUAL_SHA="$(_sha_a)"

    run deploy_import_vdi_staged "vdi-1" "https://example.invalid/img.raw"

    [ "$status" -eq 0 ]
    grep -q "import_raw_vdi" "$CMDLOG"
}

# A private mirror may not publish sums. That warns rather than blocking the
# deploy -- otherwise adding verification breaks every custom image URL.
@test "an origin with no SHA512SUMS warns but still imports" {
    _import_stub
    SUMS_BODY=""
    unset XO_DEPLOY_IMAGE_SHA512

    run deploy_import_vdi_staged "vdi-1" "https://example.invalid/img.raw"

    [ "$status" -eq 0 ]
    [[ "$output" == *"cannot be verified"* ]]
    grep -q "import_raw_vdi" "$CMDLOG"
}

# A pin is a demand for proof: unlike the published-sums path, failing to
# produce one is fatal rather than a warning.
@test "a pinned digest that cannot be computed refuses the import" {
    _import_stub
    SUMS_BODY=""
    ACTUAL_SHA=""
    XO_DEPLOY_IMAGE_SHA512="$(_sha_a)"

    run deploy_import_vdi_staged "vdi-1" "https://example.invalid/img.raw"

    [ "$status" -eq 1 ]
    ! grep -q "import_raw_vdi" "$CMDLOG"
}

@test "a pinned digest overrides the origin's own SHA512SUMS" {
    _import_stub
    # The origin says one thing, the operator pinned another. The pin wins, and
    # an image matching only the origin is refused.
    SUMS_BODY="$(_sha_b)  img.raw"
    ACTUAL_SHA="$(_sha_b)"
    XO_DEPLOY_IMAGE_SHA512="$(_sha_a)"

    run deploy_import_vdi_staged "vdi-1" "https://example.invalid/img.raw"

    [ "$status" -eq 1 ]
    [[ "$output" == *"does not match"* ]]
    ! grep -q "import_raw_vdi" "$CMDLOG"
}

# Streaming feeds the origin straight into the VDI, so there is no file to
# hash. Honouring a pin by importing an unverified image would make the pin
# mean whatever the host's free space happened to allow.
@test "streaming is refused outright when a digest is pinned" {
    _import_stub
    FREE_MB=10
    XO_DEPLOY_IMAGE_SHA512="$(_sha_a)"

    run deploy_import_vdi_from_url "vdi-1" "https://example.invalid/img.raw"

    [ "$status" -eq 1 ]
    [[ "$output" == *"cannot be verified"* ]]
    ! grep -q -- "bash -s --" "$CMDLOG"
}

# ...but with no pin, a host short on scratch space still streams as before.
@test "streaming still happens without a pin when there is no room to stage" {
    _import_stub
    FREE_MB=10
    unset XO_DEPLOY_IMAGE_SHA512

    run deploy_import_vdi_from_url "vdi-1" "https://example.invalid/img.raw"

    [ "$status" -eq 0 ]
    grep -q -- "bash -s --" "$CMDLOG"
}

# --- settings inherited from the scaffolding template ----------------------
#
# --deploy builds the appliance from "Other install media", the same generic
# HVM template the template builder starts from, and inherits the same defaults
# aimed at an unknown guest. Anything not overridden becomes a permanent
# property of the XO appliance.

@test "the deployed VM is not left advertising Hyper-V enlightenment" {
    # viridian belongs to Windows guests. The base template enables it, so
    # without an explicit override the Debian appliance carries it for life.
    local body
    body=$(declare -f deploy_create_vm)
    [[ "$body" == *"platform:viridian=false"* ]]
}

@test "the deployed VM presents its vCPUs as cores on one socket" {
    local body
    body=$(declare -f deploy_create_vm)
    [[ "$body" == *"platform:cores-per-socket=\${DEPLOY_VCPUS}"* ]]
}

@test "the deployed VM gets a usable console adapter" {
    # The stock 4 MiB cirrus adapter is what leaves XO's console at 640x480,
    # and vga=std alone leaves videoram at that same 4 -- which produces an
    # unreadable console under UEFI. Both halves are set.
    local body
    body=$(declare -f deploy_create_vm)
    [[ "$body" == *"platform:vga=std"* ]]
    [[ "$body" == *"platform:videoram=8"* ]]
}

@test "the deploy image carries a full kernel, not the cloud one" {
    # See the matching template test: the cloud kernel ships no bochs driver and
    # no compiled-in efi-framebuffer, which scrambles the XO console on a UEFI
    # guest while the VM itself runs perfectly.
    [[ "$XO_DEPLOY_IMAGE_URL" != *genericcloud* ]]
    [[ "$XO_DEPLOY_IMAGE_URL" == *generic-amd64* ]]
}
