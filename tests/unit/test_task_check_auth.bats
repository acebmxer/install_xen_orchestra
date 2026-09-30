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
    # the authenticationToken cookie it was sent.
    # shellcheck disable=SC2317
    curl() {
        local out="" prev=""
        for a in "$@"; do
            [[ "$a" == authenticationToken=* ]] && echo "$a" >> "$SEEN_TOKEN_FILE"
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
