#!/usr/bin/env bats
# Invariants for the interactive menu's grid and its parallel arrays.
#
# These exist because the arrays drift silently: adding a menu item means
# MENU_NAMES, MENU_HINTS and MENU_SELECTED all have to grow together, and
# missing one produces an `unbound variable` crash at draw time under `set -u`
# rather than anything the shell catches earlier.

setup() {
    load '../helpers/mock_helpers'
    load_script
}

@test "every menu array is MENU_TOTAL entries long" {
    [ "${#MENU_NAMES[@]}" -eq "$MENU_TOTAL" ]
    [ "${#MENU_HINTS[@]}" -eq "$MENU_TOTAL" ]
    [ "${#MENU_SELECTED[@]}" -eq "$MENU_TOTAL" ]
}

@test "an even item count fills two equal columns with nothing centered" {
    MENU_NAMES=(a b c d e f g h i j)
    menu_derive_layout

    [ "$MENU_TOTAL" -eq 10 ]
    [ "$MENU_LEFT_COUNT" -eq 5 ]
    [ "$MENU_RIGHT_COUNT" -eq 5 ]
    [ "$MENU_CENTER_COUNT" -eq 0 ]
}

@test "an odd item count gives the extra item to the left column" {
    MENU_NAMES=(a b c d e f g h i)
    menu_derive_layout

    [ "$MENU_TOTAL" -eq 9 ]
    [ "$MENU_LEFT_COUNT" -eq 5 ]
    [ "$MENU_RIGHT_COUNT" -eq 4 ]
    [ "$MENU_CENTER_COUNT" -eq 0 ]
}

@test "the grid always accounts for exactly every item" {
    local n
    for n in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
        MENU_NAMES=()
        local i
        for ((i = 0; i < n; i++)); do MENU_NAMES+=("item$i"); done
        menu_derive_layout

        [ "$((MENU_LEFT_COUNT + MENU_RIGHT_COUNT + MENU_CENTER_COUNT))" -eq "$n" ]
        # draw_menu iterates rows up to MENU_LEFT_COUNT and skips right-column
        # slots past MENU_RIGHT_COUNT, so a shorter left column loses rows.
        [ "$MENU_LEFT_COUNT" -ge "$MENU_RIGHT_COUNT" ]
        # The layout is always two columns: nothing is ever centered, and the
        # left column runs at most one row longer than the right.
        [ "$MENU_CENTER_COUNT" -eq 0 ]
        [ "$((MENU_LEFT_COUNT - MENU_RIGHT_COUNT))" -le 1 ]
    done
}

@test "position and cursor mapping round-trip for every index" {
    local idx
    for ((idx = 0; idx < MENU_TOTAL; idx++)); do
        menu_get_pos "$idx"
        MENU_CURSOR=-1
        menu_set_cursor "$MCOL" "$MROW"
        [ "$MENU_CURSOR" -eq "$idx" ]
    done
}

@test "menu_set_cursor ignores rows outside the list" {
    MENU_CURSOR=3

    menu_set_cursor 0 -1
    [ "$MENU_CURSOR" -eq 3 ]

    menu_set_cursor 1 "$MENU_TOTAL"
    [ "$MENU_CURSOR" -eq 3 ]
}

@test "every item index renders without an unbound variable" {
    ML_HINTS=1
    local idx
    for ((idx = 0; idx < MENU_TOTAL; idx++)); do
        run menu_render_item "$idx" 60
        [ "$status" -eq 0 ]
        [ -z "$output" ]
    done
}

@test "run_menu resets a selection entry for every item" {
    # run_menu itself takes over the terminal, so just the reset block is
    # exercised here — that is where the array length used to be hardcoded.
    local reset_block
    reset_block=$(awk '/# Reset selection state/,/# Gather version/' \
        "${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh" | grep -v '# Gather version')

    MENU_SELECTED=(1 1 1)
    eval "_reset() { ${reset_block} ; }"
    _reset

    [ "${#MENU_SELECTED[@]}" -eq "$MENU_TOTAL" ]
    local i
    for ((i = 0; i < MENU_TOTAL; i++)); do
        [ "${MENU_SELECTED[$i]}" -eq 0 ]
    done
}
