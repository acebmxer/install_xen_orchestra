#!/usr/bin/env bats
# Tests for check_eol_distro() -- the gate that warns on, then refuses, a
# distribution whose support this installer has dropped.
#
# Worth covering carefully because it is enforcement logic keyed to a date in
# the future: nothing exercises the refusing branch in normal use until the day
# it fires, and by then a mistake stops every run on that release. The date is
# faked here rather than waited for.

setup() {
    load '../helpers/mock_helpers'
    load_script
    ALLOW_EOL_DISTRO=false
}

# Run the gate as though the clock read $1 (YYYYMMDD).
run_on_date() {
    local when="$1"
    run env -i bash -c "
        _XO_SOURCE_ONLY=1 source '${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh'
        OS_ID='${OS_ID}'
        OS_VERSION_ID='${OS_VERSION_ID}'
        ALLOW_EOL_DISTRO='${ALLOW_EOL_DISTRO}'
        date() { echo '${when}'; }
        check_eol_distro
    "
}

# --- table shape -----------------------------------------------------------

@test "every EOL row has all six fields" {
    local row
    for row in "${XO_EOL_DISTROS[@]}"; do
        [ "$(awk -F'|' '{print NF}' <<< "$row")" -eq 6 ]
    done
}

@test "every EOL row carries dates in YYYY-MM-DD form" {
    local row eol removal
    for row in "${XO_EOL_DISTROS[@]}"; do
        eol=$(cut -d'|' -f4 <<< "$row")
        removal=$(cut -d'|' -f5 <<< "$row")
        [[ "$eol" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]
        [[ "$removal" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]
    done
}

@test "removal never precedes the upstream end-of-life it follows" {
    local row eol removal
    for row in "${XO_EOL_DISTROS[@]}"; do
        eol=$(cut -d'|' -f4 <<< "$row" | tr -d '-')
        removal=$(cut -d'|' -f5 <<< "$row" | tr -d '-')
        (( 10#$removal >= 10#$eol ))
    done
}

@test "every EOL row names a replacement to upgrade to" {
    local row advice
    for row in "${XO_EOL_DISTROS[@]}"; do
        advice=$(cut -d'|' -f6 <<< "$row")
        [ -n "$advice" ]
        [[ "$advice" =~ [Uu]pgrade ]]
    done
}

# --- Ubuntu 22.04 ----------------------------------------------------------

@test "Ubuntu 22.04 warns but runs before its removal date" {
    OS_ID=ubuntu OS_VERSION_ID=22.04
    run_on_date 20270531
    [ "$status" -eq 0 ]
    [[ "$output" == *"2027-06-01"* ]]
}

@test "Ubuntu 22.04 is refused from its removal date" {
    OS_ID=ubuntu OS_VERSION_ID=22.04
    run_on_date 20270601
    [ "$status" -eq 1 ]
    [[ "$output" == *"no longer supported"* ]]
    [[ "$output" == *"--allow-eol-distro"* ]]
}

@test "Ubuntu 22.04 past its removal date still runs with the override" {
    OS_ID=ubuntu OS_VERSION_ID=22.04 ALLOW_EOL_DISTRO=true
    run_on_date 20270601
    [ "$status" -eq 0 ]
    [[ "$output" == *"continuing anyway"* ]]
}

@test "the refusal points at the supported Ubuntu releases" {
    OS_ID=ubuntu OS_VERSION_ID=22.04
    run_on_date 20270601
    [[ "$output" == *"24.04"* ]]
    [[ "$output" == *"26.04"* ]]
}

# --- supported releases are untouched --------------------------------------

@test "Ubuntu 24.04 and 26.04 pass silently, even long after 22.04 goes" {
    local v
    for v in 24.04 26.04; do
        OS_ID=ubuntu OS_VERSION_ID="$v"
        run_on_date 20300101
        [ "$status" -eq 0 ]
        [ -z "$output" ]
    done
}

@test "Debian 12 and 13 pass silently" {
    local v
    for v in 12 13; do
        OS_ID=debian OS_VERSION_ID="$v"
        run_on_date 20300101
        [ "$status" -eq 0 ]
        [ -z "$output" ]
    done
}

@test "a distribution not in the table is never gated" {
    OS_ID=fedora OS_VERSION_ID=44
    run_on_date 20300101
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

# --- Debian 11, unchanged by the table rewrite -----------------------------

@test "Debian 11 warns before its removal date and is refused after" {
    OS_ID=debian OS_VERSION_ID=11
    run_on_date 20260904
    [ "$status" -eq 0 ]
    [[ "$output" == *"2026-10-01"* ]]

    OS_ID=debian OS_VERSION_ID=11
    run_on_date 20261001
    [ "$status" -eq 1 ]
}

# --- version matching ------------------------------------------------------

@test "matching is on the major version, so point releases are caught" {
    # Ubuntu reports VERSION_ID as "22.04"; Debian reports "11". Both have to
    # match the same major-version field, or a gate silently stops working.
    OS_ID=ubuntu OS_VERSION_ID=22.04.5
    run_on_date 20270601
    [ "$status" -eq 1 ]
}

@test "a near-miss version is not gated" {
    # 2.04 and 122.04 must not match 22 -- a substring match here would refuse
    # a release that is perfectly supported.
    local v
    for v in 2.04 122.04 24.04; do
        OS_ID=ubuntu OS_VERSION_ID="$v"
        run_on_date 20270601
        [ "$status" -eq 0 ]
    done
}

@test "a wrong clock degrades to the warning, never to a refusal" {
    # An unreadable clock yields the 00000000 fallback, which is before every
    # removal date -- so the gate warns rather than locking the operator out of
    # their own install because the machine's date is wrong.
    #
    # Only the gate's own +%Y%m%d call is broken. Stubbing date outright would
    # also break the logger, which timestamps every line with it, and the test
    # would then fail for a reason that has nothing to do with the clock.
    date() {
        if [[ "$1" == "+%Y%m%d" ]]; then
            return 1
        fi
        command date "$@"
    }

    OS_ID=ubuntu
    OS_VERSION_ID=22.04
    ALLOW_EOL_DISTRO=false

    run check_eol_distro
    [ "$status" -eq 0 ]
    [[ "$output" == *"being removed"* ]]
}
