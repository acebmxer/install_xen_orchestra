#!/usr/bin/env bats
# bash keeps one EXIT trap, so cleanups that each set their own replaced one
# another: running two menu items in one pass (Deploy, then the Template
# Library) skipped the first one's cleanup and left its work directory, with
# the deploy key in it, in /tmp. They are now registered with
# add_exit_cleanup. Each case runs in its own bash so the EXIT trap fires.

SCRIPT="${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"

run_cleanup_case() {
    bash -c '_XO_SOURCE_ONLY=1 source "$1"; set +e; trap - ERR; '"$1" _ "$SCRIPT"
}

@test "two registered cleanups both run, the later one first" {
    run run_cleanup_case 'add_exit_cleanup "echo A"; add_exit_cleanup "echo B"'
    [ "$status" -eq 0 ]
    [ "$output" = $'B\nA' ]
}

@test "a cleanup removed by hand does not run, the others do" {
    run run_cleanup_case 'add_exit_cleanup "echo A"; add_exit_cleanup "echo B"; remove_exit_cleanup "echo A"'
    [ "$output" = "B" ]
}

@test "registering the same cleanup twice runs it once" {
    run run_cleanup_case 'add_exit_cleanup "echo A"; add_exit_cleanup "echo A"'
    [ "$output" = "A" ]
}

@test "a failing cleanup does not stop the ones registered before it" {
    run run_cleanup_case 'add_exit_cleanup "echo A"; add_exit_cleanup "false"; add_exit_cleanup "echo C"'
    [ "$output" = $'C\nA' ]
}

@test "cleanups run on exit and the exit status is kept" {
    run run_cleanup_case 'add_exit_cleanup "echo A"; exit 3'
    [ "$status" -eq 3 ]
    [ "$output" = "A" ]
}

@test "the first work directory is removed when a second item registers its own" {
    local out="${BATS_TEST_TMPDIR:-$(mktemp -d)}"
    OUT="$out" run run_cleanup_case '
        d1=$(mktemp -d); d2=$(mktemp -d)
        printf "%s\n" "$d1" "$d2" > "$OUT/dirs"
        add_exit_cleanup "rm -rf $d1"
        add_exit_cleanup "rm -rf $d2"
    '
    [ "$status" -eq 0 ]
    local d n=0
    while read -r d; do [ ! -e "$d" ]; n=$((n + 1)); done < "$out/dirs"
    [ "$n" -eq 2 ]
}

@test "nothing outside the helper and the menu picker sets the EXIT trap" {
    # Allowed: the dispatcher the helper installs, the picker (which chains the
    # trap it finds), and the expect helper's heredoc (its own process).
    run bash -c "grep -nE '^[[:space:]]*trap .* EXIT' '$SCRIPT' | grep -vF -e 'trap run_exit_cleanups EXIT' -e 'trap -- ' -e 'trap -p EXIT' -e \"trap 'rm -rf \\\"\\\$d\\\"' EXIT\" -e 'trap - EXIT'"
    [ "$status" -ne 0 ]
    # The picker's own restore is the only bare `trap - EXIT` left.
    run grep -cE '^[[:space:]]*trap - EXIT' "$SCRIPT"
    [ "$output" -eq 1 ]
}
