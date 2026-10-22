#!/usr/bin/env bats
# The menu's Edit xo-config.cfg / Rename Sample items and the value flags.
#
# Ticking Edit or Rename together with another item used to drop the other
# item: the reload question came first, and "No" exited while "Yes" re-ran
# the script with nothing ticked. Declining the rename, or closing the editor
# without a change, still counted as "configuration changed". A quoted
# PREFERRED_EDITOR fell back to nano, and a value flag with no value either
# died silently or swallowed the next flag.

setup() {
    load '../helpers/mock_helpers'
    load_script

    CALLS="$BATS_TEST_TMPDIR/calls.log"
    : > "$CALLS"
}

# Stub everything process_menu_selections can reach, so only the ordering
# is under test. Each stub records its name.
stub_menu_operations() {
    local f
    for f in check_required_commands check_not_root check_sudo check_systemctl \
             detect_package_manager check_git load_config update_xo \
             install_xo release_lock; do
        eval "$f() { echo $f >> \"\$CALLS\"; }"
    done
    MENU_SELECTED=()
    local i
    for ((i = 0; i < MENU_TOTAL; i++)); do MENU_SELECTED[i]=0; done
}

@test "Edit + Update: the update still runs, then the reload is offered" {
    stub_menu_operations
    menu_edit_config() { echo menu_edit_config >> "$CALLS"; return 0; }
    prompt_yes_no() { echo prompt_yes_no >> "$CALLS"; return 1; }
    MENU_SELECTED[1]=1   # Update
    MENU_SELECTED[8]=1   # Edit xo-config.cfg

    run process_menu_selections
    [ "$status" -eq 0 ]
    [[ "$output" == *"Exiting without reload."* ]]
    # Edit, then the new file is read, then the update path, then the
    # reload question -- in that order.
    [ "$(head -2 "$CALLS" | tr '\n' ' ')" = "menu_edit_config load_config " ]
    grep -qx update_xo "$CALLS"
    [ "$(tail -1 "$CALLS")" = "prompt_yes_no" ]
    [ "$(grep -n update_xo "$CALLS" | cut -d: -f1)" -lt "$(grep -n prompt_yes_no "$CALLS" | cut -d: -f1)" ]
}

@test "Rename + Update: the update still runs" {
    stub_menu_operations
    menu_rename_config() { echo menu_rename_config >> "$CALLS"; return 0; }
    prompt_yes_no() { echo prompt_yes_no >> "$CALLS"; return 1; }
    MENU_SELECTED[1]=1   # Update
    MENU_SELECTED[2]=1   # Rename Sample

    run process_menu_selections
    [ "$status" -eq 0 ]
    grep -qx update_xo "$CALLS"
    grep -qx prompt_yes_no "$CALLS"
}

@test "Edit alone: no extra config read, the reload is still offered" {
    stub_menu_operations
    menu_edit_config() { echo menu_edit_config >> "$CALLS"; return 0; }
    prompt_yes_no() { echo prompt_yes_no >> "$CALLS"; return 1; }
    MENU_SELECTED[8]=1

    run process_menu_selections
    [ "$status" -eq 0 ]
    [ "$(cat "$CALLS" | tr '\n' ' ')" = "menu_edit_config prompt_yes_no " ]
}

@test "no config change: no reload question, other items run" {
    stub_menu_operations
    menu_edit_config() { echo menu_edit_config >> "$CALLS"; return 1; }
    prompt_yes_no() { echo prompt_yes_no >> "$CALLS"; return 1; }
    MENU_SELECTED[1]=1
    MENU_SELECTED[8]=1

    run process_menu_selections
    [ "$status" -eq 0 ]
    grep -qx update_xo "$CALLS"
    run grep -qx prompt_yes_no "$CALLS"
    [ "$status" -eq 1 ]
}

# The rename and edit prompts read /dev/tty, so these run the function
# inside a pseudo-terminal (util-linux `script`) with the answer piped in.
run_on_pty() {
    local input="$1" body="$2" driver="$BATS_TEST_TMPDIR/driver.sh"
    command -v script >/dev/null || skip "util-linux script not installed"
    cat > "$driver" <<EOF
_XO_SOURCE_ONLY=1 source "${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
set +e
CONFIG_FILE="$BATS_TEST_TMPDIR/xo-config.cfg"
SAMPLE_CONFIG="$BATS_TEST_TMPDIR/sample-xo-config.cfg"
$body
echo "rc=\$rc"
EOF
    run bash -c "printf '%s' '$input' | script -qec 'bash $driver' /dev/null"
}

@test "declining the rename's overwrite does not count as a change" {
    echo 'OLD=1' > "$BATS_TEST_TMPDIR/xo-config.cfg"
    echo 'NEW=1' > "$BATS_TEST_TMPDIR/sample-xo-config.cfg"
    run_on_pty "n" 'rc=0; menu_rename_config || rc=$?'
    [[ "$output" == *"Skipping rename."* ]]
    [[ "$output" == *"rc=1"* ]]
    [ "$(cat "$BATS_TEST_TMPDIR/xo-config.cfg")" = "OLD=1" ]
}

@test "closing the editor without a change does not count as a change" {
    printf 'PREFERRED_EDITOR=nano\n' > "$BATS_TEST_TMPDIR/xo-config.cfg"
    run_on_pty "" 'nano() { echo "nano opened $1"; }; rc=0; menu_edit_config || rc=$?'
    [[ "$output" == *"nano opened"* ]]
    [[ "$output" == *"No changes made to xo-config.cfg."* ]]
    [[ "$output" == *"rc=1"* ]]
}

@test "saving a change in the editor counts as a change" {
    printf 'PREFERRED_EDITOR=nano\n' > "$BATS_TEST_TMPDIR/xo-config.cfg"
    run_on_pty "" 'nano() { echo "HTTP_PORT=8080" >> "$1"; }; rc=0; menu_edit_config || rc=$?'
    [[ "$output" == *"Configuration editing complete."* ]]
    [[ "$output" == *"rc=0"* ]]
}

@test "a quoted PREFERRED_EDITOR with a comment is honoured" {
    printf 'PREFERRED_EDITOR="vim"   # my editor\n' > "$BATS_TEST_TMPDIR/xo-config.cfg"
    run_on_pty "" 'vim() { echo "vim opened"; }; nano() { echo "nano opened"; }; rc=0; menu_edit_config || rc=$?'
    [[ "$output" == *"vim opened"* ]]
    [[ "$output" != *"Falling back to nano"* ]]
    [[ "$output" != *"nano opened"* ]]
}

# --- value flags -------------------------------------------------------

stub_main_entry() {
    check_not_root() { echo check_not_root >> "$CALLS"; }
    self_update_script() { echo self_update_script >> "$CALLS"; }
    acquire_lock() { :; }
    run_menu() { echo run_menu >> "$CALLS"; }
}

@test "--backup-file at the end of the line is refused with a message" {
    stub_main_entry
    run main --restore --backup-file
    [ "$status" -eq 1 ]
    [[ "$output" == *"--backup-file needs a value."* ]]
    [ ! -s "$CALLS" ]
}

@test "--log-file followed by another flag does not swallow it" {
    stub_main_entry
    run main --log-file --update
    [ "$status" -eq 1 ]
    [[ "$output" == *"--log-file needs a value."* ]]
    [ ! -s "$CALLS" ]
}

@test "--log-file with a path still works" {
    stub_main_entry
    show_status() { echo "show_status LOG_FILE=$LOG_FILE" >> "$CALLS"; }
    run main --log-file "$BATS_TEST_TMPDIR/x.log" --status
    grep -q "show_status LOG_FILE=$BATS_TEST_TMPDIR/x.log" "$CALLS"
}
