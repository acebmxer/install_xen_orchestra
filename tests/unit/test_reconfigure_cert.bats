#!/usr/bin/env bats
# --reconfigure (reconfigure_xo) issues a self-signed certificate when
# SSL_CERT_DIR has none, before writing a config.toml that points at it, and
# never replaces an existing one.

setup() {
    load '../helpers/mock_helpers'
    load_script

    DRY_RUN=false
    SERVICE_USER=root
    INSTALL_DIR="$BATS_TEST_TMPDIR/xen-orchestra"
    mkdir -p "$INSTALL_DIR"
    SSL_CERT_DIR="$BATS_TEST_TMPDIR/ssl"
    SSL_CERT_FILE=xo-cert.pem
    SSL_KEY_FILE=xo-key.pem
    SSL_CERT_DAYS=825
    HTTP_PORT=80
    HTTPS_PORT=443
    REDIRECT_TO_HTTPS=false
    REDIS_URI=""
    REDIS_SOCKET=""
    DEBUG_MODE=false
    CALLS="$BATS_TEST_TMPDIR/calls.log"
    : > "$CALLS"

    # sudo runs the command (openssl, mkdir, chmod) as the test user, so the
    # certificate really gets written into the throwaway SSL_CERT_DIR.
    # shellcheck disable=SC2317
    sudo() { "$@"; }
    systemctl() { :; }
    timeout() { shift; "$@"; }
    confirm_or_skip() { return 0; }
    flush_redis_tokens() { :; }
    detect_legacy_system_state() { LEGACY_SYSTEM_CHANGES=(); }
    get_previous_service_user() { echo root; }
    # configure_xo records whether the certificate was there when the
    # config pointing at it was written.
    configure_xo() {
        if [[ -f "$SSL_CERT_DIR/$SSL_CERT_FILE" && -f "$SSL_CERT_DIR/$SSL_KEY_FILE" ]]; then
            echo "configure_xo cert-present" >> "$CALLS"
        else
            echo "configure_xo cert-missing" >> "$CALLS"
        fi
    }
    create_systemd_service() { :; }
    configure_sudo() { :; }
    configure_xenstore_access() { :; }
    cleanup_stale_service_user() { :; }
    configure_firewall() { :; }
    wait_for_xo_ready() { :; }
    detect_server_ip() { echo 127.0.0.1; }
}

@test "reconfigure issues a certificate when SSL_CERT_DIR has none" {
    command -v openssl >/dev/null || skip "openssl not installed"
    run reconfigure_xo
    [ "$status" -eq 0 ]
    grep -q '^configure_xo cert-present$' "$CALLS"
    openssl x509 -noout -in "$SSL_CERT_DIR/$SSL_CERT_FILE"
}

@test "reconfigure leaves an existing certificate untouched" {
    mkdir -p "$SSL_CERT_DIR"
    echo "my own cert" > "$SSL_CERT_DIR/$SSL_CERT_FILE"
    echo "my own key" > "$SSL_CERT_DIR/$SSL_KEY_FILE"
    run reconfigure_xo
    [ "$status" -eq 0 ]
    [[ "$output" == *"already exist"* ]]
    [ "$(cat "$SSL_CERT_DIR/$SSL_CERT_FILE")" = "my own cert" ]
    [ "$(cat "$SSL_CERT_DIR/$SSL_KEY_FILE")" = "my own key" ]
    grep -q '^configure_xo cert-present$' "$CALLS"
}
