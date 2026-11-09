#!/usr/bin/env bats
# The --proxy prompts must read with -r. Without it bash drops every
# backslash, so a password or token containing one reaches ssh, the expect
# helper and XO changed and the login fails as if the password were wrong.

setup() {
    SCRIPT="${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
}

# install_xo_proxy's body, from its definition to the next top-level "}".
proxy_body() {
    awk '/^install_xo_proxy\(\) \{/{p=1} p{print} p&&/^\}/{exit}' "$SCRIPT"
}

@test "every read in install_xo_proxy uses -r" {
    run bash -c "$(declare -f proxy_body); SCRIPT='$SCRIPT'; proxy_body | grep -vE '^[[:space:]]*#' | grep -nE '(^|[^a-z_])read ' | grep -vE 'read -[a-zA-Z]*r'"
    [ "$status" -eq 1 ]
    [ -z "$output" ]
}

@test "install_xo_proxy has the ten prompts the check covers" {
    run bash -c "$(declare -f proxy_body); SCRIPT='$SCRIPT'; proxy_body | grep -vE '^[[:space:]]*#' | grep -cE '(^|[^a-z_])read -[a-zA-Z]*r'"
    [ "$output" -ge 10 ]
}

@test "read -rsp keeps a backslash that read -sp drops" {
    run bash -c 'read -rsp "" v <<< '"'"'pa\ss'"'"'; echo "$v"'
    [ "$output" = 'pa\ss' ]
}

# --- address validation at the --proxy prompts ----------------------------

@test "--proxy prompts check what they read with the shared validators" {
    run bash -c "$(declare -f proxy_body); SCRIPT='$SCRIPT'; proxy_body | grep -vE '^[[:space:]]*#'"
    [[ "$output" == *'is_ipv4 "$POOL_MASTER_IP"'* ]]
    [[ "$output" == *'is_ipv4_or_dhcp "$PROXY_IP"'* ]]
    [[ "$output" == *'is_host_or_ipv4 "$NTP_SERVER"'* ]]
}

@test "the IPv4 shape pattern is written once" {
    run grep -cF '[0-9]{1,3}\.){3}[0-9]{1,3}' "$SCRIPT"
    [ "$output" -eq 1 ]
}

@test "is_ipv4_or_dhcp takes dhcp and real addresses only" {
    load '../helpers/mock_helpers'; load_script
    is_ipv4_or_dhcp dhcp
    is_ipv4_or_dhcp DHCP
    is_ipv4_or_dhcp 10.0.0.5
    ! is_ipv4_or_dhcp 10.0.0.
    ! is_ipv4_or_dhcp "foo bar"
    ! is_ipv4_or_dhcp 999.999.999.999
}

@test "is_host_or_ipv4 takes names and real addresses only" {
    load '../helpers/mock_helpers'; load_script
    is_host_or_ipv4 pool.ntp.org
    is_host_or_ipv4 ntp1
    is_host_or_ipv4 192.168.1.1
    ! is_host_or_ipv4 "foo bar"
    ! is_host_or_ipv4 10.0.0.
    ! is_host_or_ipv4 999.1.1.1
    ! is_host_or_ipv4 ""
    ! is_host_or_ipv4 "a..b"
    ! is_host_or_ipv4 "-bad"
}
