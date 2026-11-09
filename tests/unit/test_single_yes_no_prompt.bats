#!/usr/bin/env bats
# There used to be four yes/no prompts, and confirm_or_skip read stdin, so
# `echo y | ./install-xen-orchestra.sh --deploy` answered "Continue?" by
# itself (#117). prompt_yes_no is now the only one: it reads the terminal.

SCRIPT="${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"

# setsid drops the controlling terminal, so /dev/tty cannot be opened and the
# only thing that could answer is stdin.
ask_with_piped_y() {
    echo y | setsid bash -c '_XO_SOURCE_ONLY=1 source "$1"; set +e; trap - ERR
        NON_INTERACTIVE=false
        if prompt_yes_no "go?"; then echo ANSWERED_YES; else echo ANSWERED_NO; fi' _ "$SCRIPT"
}

@test "a piped y does not answer the prompt" {
    run ask_with_piped_y
    [[ "$output" != *"ANSWERED_YES"* ]]
    [[ "$output" != *"ANSWERED_NO"* ]]
}

@test "confirm_or_skip is gone" {
    run grep -n 'confirm_or_skip' "$SCRIPT"
    [ "$status" -eq 1 ]
}

@test "no inline single-key y/N prompt is left" {
    run grep -nE 'read -n 1|\(y/N\)|\[y/N\]' "$SCRIPT"
    [ "$status" -eq 1 ]
}
