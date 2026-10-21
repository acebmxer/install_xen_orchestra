#!/usr/bin/env bats
# GIT_BRANCH must be a branch: require_remote_branch() refuses a tag or a
# missing branch, and --rebuild keeps the current install when the fresh
# clone fails.

setup() {
    load '../helpers/mock_helpers'
    load_script

    DRY_RUN=false
    GIT_BRANCH=master
    SERVICE_USER=root

    # Stand-in for `git ls-remote --exit-code`: STUB_HEADS / STUB_TAGS are the
    # exit codes for the --heads and --tags lookups (0 match, 2 no match,
    # 128 unreachable). STUB_CLONE is the exit code of `git clone`; on
    # success it creates the target directory with a marker file.
    STUB_HEADS=0
    STUB_TAGS=2
    STUB_CLONE=0
    git() {
        case "$1 $2 $3" in
            "ls-remote --exit-code --heads") return "$STUB_HEADS" ;;
            "ls-remote --exit-code --tags") return "$STUB_TAGS" ;;
        esac
        if [[ "$1" == "clone" ]]; then
            [[ "$STUB_CLONE" -eq 0 ]] || return "$STUB_CLONE"
            local target="${*: -1}"
            mkdir -p "$target" && echo fresh > "$target/marker"
            return 0
        fi
        return 0
    }
}

@test "require_remote_branch: an existing branch passes" {
    run require_remote_branch
    [ "$status" -eq 0 ]
}

@test "require_remote_branch: a tag is refused as a tag" {
    STUB_HEADS=2
    STUB_TAGS=0
    GIT_BRANCH=v5.100.0
    run require_remote_branch
    [ "$status" -eq 1 ]
    [[ "$output" == *"GIT_BRANCH=v5.100.0 is a tag"* ]]
}

@test "require_remote_branch: a missing branch is refused as missing" {
    STUB_HEADS=2
    STUB_TAGS=2
    GIT_BRANCH=stable
    run require_remote_branch
    [ "$status" -eq 1 ]
    [[ "$output" == *"GIT_BRANCH=stable: no such branch"* ]]
}

@test "require_remote_branch: GitHub unreachable is reported as such" {
    STUB_HEADS=128
    run require_remote_branch
    [ "$status" -eq 1 ]
    [[ "$output" == *"Could not reach"* ]]
}

@test "require_remote_branch: checks the branch passed as an argument" {
    git() {
        [[ "$*" == *"refs/heads/feature-x"* ]] && return 0
        return 2
    }
    run require_remote_branch feature-x
    [ "$status" -eq 0 ]
}

# rebuild_xo with everything around the clone stubbed out. sudo runs the
# command for real (as the test user) so the directory swap can be checked.
rebuild_setup() {
    sudo() { "$@"; }
    INSTALL_DIR="$BATS_TEST_TMPDIR/xen-orchestra"
    BACKUP_DIR="$BATS_TEST_TMPDIR/backups"
    mkdir -p "$INSTALL_DIR"
    echo old > "$INSTALL_DIR/marker"
    SYSTEMCTL_LOG="$BATS_TEST_TMPDIR/systemctl.log"
    systemctl() { echo "$*" >> "$SYSTEMCTL_LOG"; }
    install_dir_git() { echo HEAD; }
    confirm_or_skip() { return 0; }
    snapshot_xo_vm() { :; }
    flush_redis_tokens() { :; }
    create_backup() { :; }
    get_previous_service_user() { echo root; }
    # First step after the swap: stop here.
    install_nodejs() { echo "REACHED_BUILD"; exit 0; }
}

@test "rebuild: a failed clone keeps the current install and restarts XO" {
    rebuild_setup
    STUB_CLONE=128
    run rebuild_xo
    [ "$status" -eq 1 ]
    [[ "$output" == *"current installation was left in place"* ]]
    [ "$(cat "$INSTALL_DIR/marker")" = "old" ]
    [ ! -e "${INSTALL_DIR}.rebuild-new" ]
    grep -q '^start xo-server' "$SYSTEMCTL_LOG"
}

@test "rebuild: a successful clone replaces the install" {
    rebuild_setup
    run rebuild_xo
    [ "$status" -eq 0 ]
    [[ "$output" == *"REACHED_BUILD"* ]]
    [ "$(cat "$INSTALL_DIR/marker")" = "fresh" ]
    [ ! -e "${INSTALL_DIR}.rebuild-new" ]
}

@test "rebuild: a detached HEAD re-clones GIT_BRANCH, not 'HEAD'" {
    rebuild_setup
    git() {
        case "$1 $2 $3" in
            "ls-remote --exit-code --heads") return 0 ;;
        esac
        if [[ "$1" == "clone" ]]; then
            [[ "$3" == "master" ]] || return 128
            mkdir -p "${*: -1}" && echo fresh > "${*: -1}/marker"
        fi
        return 0
    }
    run rebuild_xo
    [ "$status" -eq 0 ]
    [[ "$output" == *"branch: master"* ]]
    [ "$(cat "$INSTALL_DIR/marker")" = "fresh" ]
}

@test "rebuild: a tag in GIT_BRANCH is refused before XO is stopped" {
    rebuild_setup
    STUB_HEADS=2
    STUB_TAGS=0
    GIT_BRANCH=v5.100.0
    run rebuild_xo
    [ "$status" -eq 1 ]
    [[ "$output" == *"is a tag"* ]]
    [ "$(cat "$INSTALL_DIR/marker")" = "old" ]
    [ ! -e "$SYSTEMCTL_LOG" ]
}

@test "update: a tag in GIT_BRANCH is refused with the tag message" {
    INSTALL_DIR="$BATS_TEST_TMPDIR/xen-orchestra"
    mkdir -p "$INSTALL_DIR"
    STUB_HEADS=2
    STUB_TAGS=0
    GIT_BRANCH=v5.100.0
    run update_xo
    [ "$status" -eq 1 ]
    [[ "$output" == *"is a tag"* ]]
}
