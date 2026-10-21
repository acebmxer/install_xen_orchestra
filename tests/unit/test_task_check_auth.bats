#!/usr/bin/env bats
# Tests for which token check_active_xo_tasks() in install-xen-orchestra.sh
# authenticates with. Regression: it read only XO_TASK_CHECK_TOKEN, so a
# config that set only XO_API_TOKEN skipped the check under --non-interactive.

setup() {
    load '../helpers/mock_helpers'
    load_script

    HTTPS_PORT=443
    HTTP_PORT=80
    NON_INTERACTIVE=true
    unset XO_TASK_CHECK_USER XO_TASK_CHECK_PASS

    SEEN_TOKEN_FILE=$(mktemp)
    export SEEN_TOKEN_FILE
    # Answers the task query with 200 and an empty task list, and records
    # the authenticationToken cookie it was sent. The cookie arrives in the
    # curl config given with -K (see xo_cookie_config), not on the command line.
    # shellcheck disable=SC2317
    curl() {
        local out="" prev=""
        for a in "$@"; do
            [[ "$prev" == "-K" ]] && sed -n 's/^cookie = "\(authenticationToken=[^"]*\)"$/\1/p' "$a" >> "$SEEN_TOKEN_FILE"
            [[ "$prev" == "--output" ]] && out="$a"
            prev="$a"
        done
        [[ -n "$out" ]] && echo "[]" > "$out"
        echo "200"
    }
    export -f curl
}

teardown() {
    rm -f "$SEEN_TOKEN_FILE"
}

@test "task check uses XO_API_TOKEN when only that is set" {
    XO_API_TOKEN="api-token-value"
    unset XO_TASK_CHECK_TOKEN

    run check_active_xo_tasks
    [ "$status" -eq 0 ]
    [[ "$output" != *"Skipping task check"* ]]
    run cat "$SEEN_TOKEN_FILE"
    [[ "$output" == *"authenticationToken=api-token-value"* ]]
}

@test "task check falls back to XO_TASK_CHECK_TOKEN when XO_API_TOKEN is unset" {
    unset XO_API_TOKEN
    XO_TASK_CHECK_TOKEN="legacy-token-value"

    run check_active_xo_tasks
    [ "$status" -eq 0 ]
    run cat "$SEEN_TOKEN_FILE"
    [[ "$output" == *"authenticationToken=legacy-token-value"* ]]
}

@test "task check skips under --non-interactive when no token or credentials are set" {
    unset XO_API_TOKEN XO_TASK_CHECK_TOKEN

    run check_active_xo_tasks
    [ "$status" -eq 0 ]
    [[ "$output" == *"Skipping task check"* ]]
    [ ! -s "$SEEN_TOKEN_FILE" ]
}

# Basic-auth credentials go to curl as a `user = "..."` config line. Inside
# double quotes curl's config parser treats backslash as an escape, so only
# escaping `"` turned a password like pa\ss\nword into "pass", a newline and
# "word": a 401, and under --non-interactive the check was skipped. Sent here
# with the real curl to a local server that decodes what arrived.
@test "a password with backslashes and quotes reaches XO unchanged" {
    command -v curl >/dev/null || skip "curl not installed"
    command -v python3 >/dev/null || skip "python3 not installed"
    unset -f curl
    local dir
    dir=$(mktemp -d)
    cat > "${dir}/server.py" <<'PY'
import base64, http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Basic "):
            with open(sys.argv[1], "ab") as f:
                f.write(base64.b64decode(auth[6:]) + b"\n")
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
    python3 "${dir}/server.py" "${dir}/seen" "${dir}/port" &
    local server_pid=$! i
    for i in $(seq 1 50); do [[ -s "${dir}/port" ]] && break; sleep 0.1; done
    HTTPS_PORT=$(cat "${dir}/port")
    HTTP_PORT="$HTTPS_PORT"
    unset XO_API_TOKEN XO_TASK_CHECK_TOKEN
    XO_TASK_CHECK_USER='ad"min'
    XO_TASK_CHECK_PASS='pa\ss\nwo"rd\'

    run check_active_xo_tasks
    kill "$server_pid" 2>/dev/null || true

    [ "$status" -eq 0 ]
    [ "$(cat "${dir}/seen")" = 'ad"min:pa\ss\nwo"rd\' ]
    rm -rf "$dir"
}
