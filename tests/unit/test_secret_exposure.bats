#!/usr/bin/env bats
# Passwords and tokens must not reach places other local users, or a pasted
# bug report, can read: a process's command line (ps, /proc/<pid>/cmdline),
# the XO_DEBUG trace, or the --log-file.

setup() {
    load '../helpers/mock_helpers'
    load_script

    TMPDIR_TEST=$(mktemp -d)
    SCRIPT="${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
}

teardown() {
    [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null
    [[ -n "${TMPDIR_TEST:-}" ]] && rm -rf "$TMPDIR_TEST"
}

# A local HTTP server that records the Cookie header of each request and
# answers slowly, so a test can look at curl's command line while it waits.
_start_cookie_server() {
    command -v python3 >/dev/null || skip "python3 not installed"
    cat > "${TMPDIR_TEST}/server.py" <<'PY'
import http.server, sys, time
log = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(log, "a") as f:
            f.write((self.headers.get("Cookie") or "") + "\n")
        time.sleep(1.5)
        body = b"[]"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[2], "w").write(str(s.server_port))
s.serve_forever()
PY
    python3 "${TMPDIR_TEST}/server.py" "${TMPDIR_TEST}/cookies" "${TMPDIR_TEST}/port" &
    SERVER_PID=$!
    local i
    for i in $(seq 1 50); do
        [[ -s "${TMPDIR_TEST}/port" ]] && break
        sleep 0.1
    done
    SERVER_PORT=$(cat "${TMPDIR_TEST}/port")
}

@test "no curl call in the script puts the XO token on its command line" {
    # The token reaches curl only through xo_cookie_config. The one remaining
    # authenticationToken= on a command line is xo-cli proxy.register, which
    # takes it no other way.
    run grep -nE '(-b|--cookie) +"?authenticationToken=' "$SCRIPT"
    [ "$status" -ne 0 ]
    run grep -nE 'authenticationToken=\$' "$SCRIPT"
    [ "$status" -ne 0 ]
}

@test "the token reaches XO intact, including quotes and backslashes" {
    command -v curl >/dev/null || skip "curl not installed"
    _start_cookie_server
    local tok='abc"def\ghi\nend'
    run curl -s -K <(xo_cookie_config tok) "http://127.0.0.1:${SERVER_PORT}/"
    [ "$status" -eq 0 ]
    [ "$(cat "${TMPDIR_TEST}/cookies")" = "authenticationToken=${tok}" ]
}

@test "the running-task check's curl does not show the token in ps" {
    command -v curl >/dev/null || skip "curl not installed"
    _start_cookie_server
    XO_API_TOKEN="secret-token-123"
    HTTPS_PORT="$SERVER_PORT"
    HTTP_PORT="$SERVER_PORT"
    NON_INTERACTIVE=true

    check_active_xo_tasks > "${TMPDIR_TEST}/out" 2>&1 &
    local check_pid=$! i p
    : > "${TMPDIR_TEST}/cmdlines"
    for i in $(seq 1 40); do
        for p in /proc/[0-9]*; do
            [[ "$(command cat "$p/comm" 2>/dev/null)" == "curl" ]] || continue
            tr '\0' ' ' < "$p/cmdline" >> "${TMPDIR_TEST}/cmdlines" 2>/dev/null
            echo >> "${TMPDIR_TEST}/cmdlines"
        done
        sleep 0.05
    done
    wait "$check_pid"

    # curl was seen running, and never with the token in its command line.
    grep -q ":${SERVER_PORT}/" "${TMPDIR_TEST}/cmdlines"
    run grep -q "secret-token-123" "${TMPDIR_TEST}/cmdlines"
    [ "$status" -eq 1 ]
    grep -qx "authenticationToken=secret-token-123" "${TMPDIR_TEST}/cookies"
}

@test "xo_cli_write_config keeps existing settings and writes the file 0600" {
    command -v node >/dev/null || skip "node not installed"
    mkdir -p "${TMPDIR_TEST}/xo-cli"
    printf '{"clientId":"keepme","other":1,"token":"old"}' > "${TMPDIR_TEST}/xo-cli/config.json"
    chmod 644 "${TMPDIR_TEST}/xo-cli/config.json"
    local tok='new"tok\en'

    xo_cli_write_config "$TMPDIR_TEST" "https://xo.example.test" tok

    run node -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1]));
        console.log([c.clientId, c.other, c.server, c.allowUnauthorized, c.token===process.argv[2]].join(" "))' \
        "${TMPDIR_TEST}/xo-cli/config.json" "$tok"
    [ "$output" = "keepme 1 https://xo.example.test true true" ]
    [ "$(stat -c '%a' "${TMPDIR_TEST}/xo-cli/config.json")" = "600" ]
}

@test "--proxy passes the XO password to the xo-cli login by environment" {
    # The expect script reads it from XO_CLI_REG_PASSWORD; no call passes
    # $XO_PASSWORD as an argument, and register --token is not used.
    run grep -n 'set password \$env(XO_CLI_REG_PASSWORD)' "$SCRIPT"
    [ "$status" -eq 0 ]
    run grep -nE '"\$XO_CLI_SCRIPT".*\$XO_PASSWORD' "$SCRIPT"
    [ "$status" -ne 0 ]
    run grep -nE '^[[:space:]]*[^#[:space:]].*xo-cli register .*--token' "$SCRIPT"
    [ "$status" -ne 0 ]
}

@test "the proxy token is never written to the log file in full" {
    # Only ${AUTH_TOKEN:0:20} may go through log_*; the manual command that
    # needs the whole token is echoed to the terminal only.
    run grep -nE 'log_(info|success|warning|error) .*\$\{?AUTH_TOKEN([^:]|$)' "$SCRIPT"
    [ "$status" -ne 0 ]
}

@test "XO_DEBUG's trace leaves out the config file's secrets" {
    CONFIG_FILE="${TMPDIR_TEST}/xo-config.cfg"
    cat > "$CONFIG_FILE" <<'EOF'
CONFIG_VERSION=99
XO_API_TOKEN=trace-secret-token
XO_TASK_CHECK_PASS=trace-secret-pass
EOF
    chmod 600 "$CONFIG_FILE"
    migrate_config() { :; }

    set -x
    load_config 2> "${TMPDIR_TEST}/trace"
    set +x

    [ -s "${TMPDIR_TEST}/trace" ]
    run grep -q "trace-secret" "${TMPDIR_TEST}/trace"
    [ "$status" -eq 1 ]
}

@test "XO_DEBUG's trace leaves out the token in the task check and the snapshot" {
    XO_API_TOKEN="trace-secret-token"
    HTTPS_PORT=1
    HTTP_PORT=1
    NON_INTERACTIVE=true
    # shellcheck disable=SC2317
    curl() { echo "200"; }
    # shellcheck disable=SC2317
    systemd-detect-virt() { echo "xen"; }
    # shellcheck disable=SC2317
    cat() {
        if [[ "$1" == "/sys/hypervisor/uuid" ]]; then echo "vm-uuid-123"; return 0; fi
        command cat "$@"
    }

    set -x
    check_active_xo_tasks > /dev/null 2> "${TMPDIR_TEST}/trace" || true
    snapshot_xo_vm "pre-update" > /dev/null 2>> "${TMPDIR_TEST}/trace" || true
    { : trace-was-on; } 2>> "${TMPDIR_TEST}/trace"
    set +x

    grep -q "trace-was-on" "${TMPDIR_TEST}/trace"
    run grep -q "trace-secret" "${TMPDIR_TEST}/trace"
    [ "$status" -eq 1 ]
}

@test "a function that pauses the trace turns it back on when it returns" {
    run bash -c '
        _XO_SOURCE_ONLY=1 source "$1"
        set +e
        CONFIG_FILE=$(mktemp)
        printf "CONFIG_VERSION=99\n" > "$CONFIG_FILE"; chmod 600 "$CONFIG_FILE"
        migrate_config() { :; }
        set -x
        load_config >/dev/null 2>&1
        [[ $- == *x* ]] && echo TRACE_BACK_ON
        rm -f "$CONFIG_FILE"
    ' _ "$SCRIPT"
    [[ "$output" == *"TRACE_BACK_ON"* ]]
}
