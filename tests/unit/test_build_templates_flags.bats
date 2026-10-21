#!/usr/bin/env bats
# --build-templates and the automation flags: --dry-run used to build for
# real (the build steps call the pool and XO directly, not through run_cmd),
# and --non-interactive opened the picker anyway, which read EOF as Enter and
# quit "successfully" with nothing selected.

setup() {
    load '../helpers/mock_helpers'
    load_script

    CALLS="$BATS_TEST_TMPDIR/calls.log"
    : > "$CALLS"

    check_not_root() { :; }
    self_update_script() { :; }
    acquire_lock() { :; }
    check_required_commands() { :; }
    load_config() { :; }
    build_vm_templates() { echo "build_vm_templates" >> "$CALLS"; }
}

@test "--build-templates with --non-interactive is refused before the build starts" {
    run main --build-templates --non-interactive
    [ "$status" -eq 1 ]
    [[ "$output" == *"--build-templates cannot be combined with --non-interactive"* ]]
    [ ! -s "$CALLS" ]
}

@test "--build-templates without --non-interactive still reaches the build" {
    run main --build-templates
    [ "$status" -eq 0 ]
    [ "$(cat "$CALLS")" = "build_vm_templates" ]
}

@test "--non-interactive without an operation lists --status, not the refused --deploy" {
    run main --non-interactive
    [ "$status" -eq 1 ]
    [[ "$output" == *"--status"* ]]
    [[ "$output" != *"--deploy"* ]]
    [[ "$output" != *"--build-templates"* ]]
}

# The real build_vm_templates from here on: reload the script so the stub
# from setup() is replaced.
@test "--dry-run stops build_vm_templates before any check, prompt or pool call" {
    load_script
    DRY_RUN=true
    tpl_check_local_deps() { echo "tpl_check_local_deps" >> "$CALLS"; }
    tpl_prompt_selection() { echo "tpl_prompt_selection" >> "$CALLS"; }
    tpl_select_build_method() { echo "tpl_select_build_method" >> "$CALLS"; }
    dom0_xe() { echo "dom0_xe" >> "$CALLS"; }

    run build_vm_templates
    [ "$status" -eq 0 ]
    [[ "$output" == *"[DRY-RUN] --build-templates creates VMs and templates"* ]]
    [[ "$output" == *"No changes were made."* ]]
    [ ! -s "$CALLS" ]
}

@test "without --dry-run build_vm_templates goes on to the picker" {
    load_script
    DRY_RUN=false
    tpl_check_local_deps() { echo "tpl_check_local_deps" >> "$CALLS"; }
    tpl_prompt_selection() { echo "tpl_prompt_selection" >> "$CALLS"; TPL_SELECTED=(); }

    run build_vm_templates
    [ "$status" -eq 0 ]
    [ "$(cat "$CALLS")" = "$(printf 'tpl_check_local_deps\ntpl_prompt_selection')" ]
    [[ "$output" != *"[DRY-RUN]"* ]]
}
