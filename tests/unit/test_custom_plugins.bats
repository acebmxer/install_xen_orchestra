#!/usr/bin/env bats
# manage_custom_plugins diffs the picker's selections against its own
# preselection (already-installed plugins) to work out what to install vs.
# uninstall. That diff used to read MENU_PRESELECTED *after* the surrounding
# code had already reset it to an empty array for the main menu's sake --
# an `unbound variable` crash under `set -u` on every run of this menu,
# selecting any plugin at all.

setup() {
    load '../helpers/mock_helpers'
    load_script

    CUSTOM_PLUGIN_CATALOG=(
        "plugin-a|plugin-a|Test plugin A"
        "plugin-b|plugin-b|Test plugin B"
    )
    DRY_RUN=true
    NON_INTERACTIVE=false
    SCRIPT_DIR="${BATS_TEST_DIRNAME}/../.."

    # Stand in for the real interactive picker: selects everything, as if the
    # user checked every box. MENU_SELECTED's length has to match the catalog,
    # same contract menu_interactive_pick itself fulfills.
    menu_interactive_pick() {
        MENU_SELECTED=(1 1)
        MENU_CANCELLED=0
    }

    installed=()
    install_custom_plugin() { installed+=("$1"); }
    uninstalled=()
    uninstall_custom_plugin() { uninstalled+=("$1"); }
}

@test "selecting every plugin does not crash on an unbound MENU_PRESELECTED" {
    run manage_custom_plugins
    [ "$status" -eq 0 ]
}

@test "selecting every plugin installs all of them" {
    manage_custom_plugins

    [ "${#installed[@]}" -eq 2 ]
    [ "${installed[0]}" = "plugin-a" ]
    [ "${installed[1]}" = "plugin-b" ]
    [ "${#uninstalled[@]}" -eq 0 ]
}
