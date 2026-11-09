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
