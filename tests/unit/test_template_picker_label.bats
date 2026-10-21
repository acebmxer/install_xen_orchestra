#!/usr/bin/env bats
# The template picker's "already on this pool" label. It used to call the SSH
# existence check for every row before any pool connection existed, so the
# check died silently and no row was ever labelled. Now, on the API path, the
# pool's templates are fetched once before the picker opens; the SSH path
# shows no label. The run summary also used to count a skipped template as
# "ready".

setup() {
    load '../helpers/mock_helpers'
    load_script

    S=$(mktemp -d)
    CALLS="$S/calls.log"
    : > "$CALLS"

    XO_API_TOKEN="test-token"
    TEMPLATE_BUILD_METHOD="auto"

    POOLS='[
  {
    "id": "pool-A",
    "default_SR": "sr-A",
    "name_label": "Pool A"
  },
  {
    "id": "pool-B",
    "default_SR": "sr-B",
    "name_label": "Pool B"
  }
]'
    TEMPLATES='[
  {
    "name_label": "Debian 12 (Bookworm) Cloud-init",
    "$pool": "pool-A"
  },
  {
    "name_label": "Debian 13 (Trixie) Cloud-init",
    "$pool": "pool-B"
  }
]'

    tpl_api_check_auth() { echo "auth" >> "$CALLS"; return 0; }
    tpl_api_get() {
        echo "GET $1" >> "$CALLS"
        case "$1" in
            pools\?*)        printf '%s' "$POOLS" ;;
            vm-templates\?*) printf '%s' "$TEMPLATES" ;;
            *)               printf '{}' ;;
        esac
    }
    deploy_choose() { echo "choose" >> "$CALLS"; DEPLOY_CHOICE="pool-B"; }
}

teardown() {
    [[ -n "${S:-}" ]] && rm -rf "$S"
}

# --- fetching what exists -------------------------------------------------

@test "with a token, the chosen pool's templates are fetched once before the picker" {
    tpl_api_prefetch_existing > /dev/null 2>&1
    [ "$TPL_EXISTING_KNOWN" = "true" ]
    [ "$TPL_API_POOL_ID" = "pool-B" ]
    tpl_existing_label "Debian 13 (Trixie) Cloud-init"
    # Built on pool A only: not "already on this pool" for pool B.
    run tpl_existing_label "Debian 12 (Bookworm) Cloud-init"
    [ "$status" -eq 1 ]
    [ "$(grep -c '^GET vm-templates' "$CALLS")" -eq 1 ]
}

@test "TEMPLATE_BUILD_METHOD=ssh fetches nothing and shows no labels" {
    TEMPLATE_BUILD_METHOD=ssh
    tpl_api_prefetch_existing > /dev/null 2>&1
    [ "$TPL_EXISTING_KNOWN" = "false" ]
    [ ! -s "$CALLS" ]
    run tpl_existing_label "Debian 13 (Trixie) Cloud-init"
    [ "$status" -eq 1 ]
}

@test "without a token nothing is fetched and nobody is asked" {
    XO_API_TOKEN=""
    tpl_api_prefetch_existing > /dev/null 2>&1
    [ "$TPL_EXISTING_KNOWN" = "false" ]
    [ ! -s "$CALLS" ]
}

@test "an XO that refuses the token gives no labels and no pool question" {
    tpl_api_check_auth() { echo "auth" >> "$CALLS"; return 1; }
    tpl_api_prefetch_existing > /dev/null 2>&1
    [ "$TPL_EXISTING_KNOWN" = "false" ]
    [ "$(cat "$CALLS")" = "auth" ]
}

@test "the pool chosen for the labels is the one the build uses, asked once" {
    tpl_api_prefetch_existing > /dev/null 2>&1
    PIFS='[]'
    tpl_api_resolve_targets > /dev/null 2>&1 || true
    [ "$(grep -c '^choose' "$CALLS")" -eq 1 ]
    [ "$DEPLOY_SR_UUID" = "sr-B" ]
}

# --- the picker -------------------------------------------------------------

_picker_stubs() {
    clear() { :; }
    menu_hide_cursor() { :; }
    menu_show_cursor() { :; }
    stty() { :; }
    menu_read_key() { MENU_KEY="QUIT"; }
    dom0_xe() { echo "dom0_xe $*" >> "$CALLS"; }
    tpl_template_exists() { echo "tpl_template_exists $*" >> "$CALLS"; return 0; }
}

@test "the picker labels the row that is on the pool, and only that row" {
    _picker_stubs
    TPL_EXISTING_KNOWN=true
    TPL_EXISTING_NAMES="Debian 13 (Trixie) Cloud-init"
    run tpl_prompt_selection
    [ "$status" -eq 0 ]
    [ "$(grep -c 'already on this pool' <<< "$output")" -eq 1 ]
    # The label sits under the Debian 13 row.
    grep -A1 'Debian 13 (Trixie)' <<< "$output" | grep -q 'already on this pool'
}

@test "the picker makes no pool calls of its own" {
    _picker_stubs
    TPL_EXISTING_KNOWN=false
    run tpl_prompt_selection
    [ "$status" -eq 0 ]
    [[ "$output" == *"VM Template Library"* ]]
    [[ "$output" != *"already on this pool"* ]]
    [ ! -s "$CALLS" ]
}

# --- the summary ------------------------------------------------------------

@test "a template that already exists is flagged as skipped" {
    tpl_template_exists_dispatch() { return 0; }
    tpl_build_one "debian-13|Debian 13 (Trixie)|trixie|https://e/x.raw|debian|tpl_prep_debian|4|bios" > /dev/null 2>&1
    [ "$TPL_SKIPPED" = "true" ]
}

@test "the summary counts skipped templates apart from built ones" {
    tpl_check_local_deps() { :; }
    tpl_api_prefetch_existing() { :; }
    tpl_prompt_selection() { TPL_SELECTED=("row-skip" "row-build"); }
    tpl_select_build_method() { TPL_BUILD_METHOD=api; }
    tpl_api_resolve_targets() { :; }
    tpl_template_name() { echo "$1"; }
    tpl_field() { echo "$1"; }
    confirm_or_skip() { return 0; }
    tpl_build_one() {
        if [[ "$1" == "row-skip" ]]; then TPL_SKIPPED=true; else TPL_SKIPPED=false; fi
        return 0
    }
    run build_vm_templates
    [ "$status" -eq 0 ]
    [[ "$output" == *"Done. 1 template(s) built, 1 skipped (already on the pool)."* ]]
    [[ "$output" != *"2 template(s)"* ]]
}

@test "with nothing skipped the summary mentions no skips" {
    tpl_check_local_deps() { :; }
    tpl_api_prefetch_existing() { :; }
    tpl_prompt_selection() { TPL_SELECTED=("row-a" "row-b"); }
    tpl_select_build_method() { TPL_BUILD_METHOD=api; }
    tpl_api_resolve_targets() { :; }
    tpl_template_name() { echo "$1"; }
    tpl_field() { echo "$1"; }
    confirm_or_skip() { return 0; }
    tpl_build_one() { TPL_SKIPPED=false; return 0; }
    run build_vm_templates
    [ "$status" -eq 0 ]
    [[ "$output" == *"Done. 2 template(s) built."* ]]
    [[ "$output" != *"skipped"* ]]
}
