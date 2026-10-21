#!/usr/bin/env bats
# The API template build takes everything from one pool. With XO managing
# several pools it used to read the first pool id and the first default_SR
# independently (possibly from different pools), take the management network,
# base template and guest-tools ISO from whichever pool XO listed first, and
# treat a same-named template on another pool as "already exists".

setup() {
    load '../helpers/mock_helpers'
    load_script

    S=$(mktemp -d)
    CALLS="$S/calls.log"
    : > "$CALLS"

    # XO lists pool A first; pool B's objects come after pool A's.
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
    PIFS='[
  {
    "management": true,
    "$network": "net-A",
    "$pool": "pool-A"
  },
  {
    "management": false,
    "$network": "net-B-storage",
    "$pool": "pool-B"
  },
  {
    "management": true,
    "$network": "net-B",
    "$pool": "pool-B"
  }
]'
    TEMPLATES='[
  {
    "id": "pool-A-tplA",
    "uuid": "tpl-A",
    "name_label": "Other install media",
    "$pool": "pool-A"
  },
  {
    "id": "pool-A-deb",
    "uuid": "deb-A",
    "name_label": "Debian 13 (Trixie) Cloud-init",
    "$pool": "pool-A"
  },
  {
    "id": "pool-B-tplB",
    "uuid": "tpl-B",
    "name_label": "Other install media",
    "$pool": "pool-B"
  }
]'
    VDIS='[
  {
    "id": "iso-A",
    "name_label": "guest-tools.iso",
    "$pool": "pool-A"
  },
  {
    "id": "iso-B",
    "name_label": "guest-tools.iso",
    "$pool": "pool-B"
  }
]'
    export POOLS PIFS TEMPLATES VDIS

    tpl_api_get() {
        echo "GET $1" >> "$CALLS"
        case "$1" in
            pools\?*)        printf '%s' "$POOLS" ;;
            pifs\?*)         printf '%s' "$PIFS" ;;
            vm-templates\?*) printf '%s' "$TEMPLATES" ;;
            vdis\?*)         printf '%s' "$VDIS" ;;
            *)               printf '{}' ;;
        esac
    }
}

teardown() {
    [[ -n "${S:-}" ]] && rm -rf "$S"
}

@test "with two pools the operator is asked, and the SR and network come from the chosen pool" {
    deploy_choose() {
        printf '%s\n' "$@" > "$S/choose"
        DEPLOY_CHOICE="pool-B"
    }
    tpl_api_resolve_targets > /dev/null 2>&1
    grep -qx 'pool-A|Pool A' "$S/choose"
    grep -qx 'pool-B|Pool B' "$S/choose"
    [ "$TPL_API_POOL_ID" = "pool-B" ]
    [ "$DEPLOY_SR_UUID" = "sr-B" ]
    [ "$DEPLOY_NETWORK_UUID" = "net-B" ]
}

@test "with one pool nobody is asked and its own SR is used" {
    POOLS='[
  {
    "id": "pool-B",
    "default_SR": "sr-B",
    "name_label": "Pool B"
  }
]'
    run tpl_api_resolve_targets < /dev/null
    [ "$status" -eq 0 ]
    [[ "$output" == *"Pool B (only option)"* ]]
    tpl_api_resolve_targets < /dev/null > /dev/null 2>&1
    [ "$DEPLOY_SR_UUID" = "sr-B" ]
    [ "$DEPLOY_NETWORK_UUID" = "net-B" ]
}

@test "a pool with no default SR is reported, not given another pool's" {
    POOLS='[
  {
    "id": "pool-A",
    "default_SR": "sr-A",
    "name_label": "Pool A"
  },
  {
    "id": "pool-B",
    "name_label": "Pool B"
  }
]'
    deploy_choose() { DEPLOY_CHOICE="pool-B"; }
    run tpl_api_resolve_targets
    [ "$status" -eq 1 ]
    [[ "$output" == *"no default SR"* ]]
}

@test "a template on another pool is not 'already on this pool'" {
    TPL_BUILD_METHOD=api
    TPL_API_POOL_ID="pool-B"
    run tpl_template_exists_dispatch "Debian 13 (Trixie) Cloud-init"
    [ "$status" -eq 1 ]
    TPL_API_POOL_ID="pool-A"
    run tpl_template_exists_dispatch "Debian 13 (Trixie) Cloud-init"
    [ "$status" -eq 0 ]
}

@test "the exists check asks XO by name rather than listing a limited page" {
    TPL_BUILD_METHOD=api
    TPL_API_POOL_ID="pool-A"
    tpl_template_exists_dispatch "Debian 13 (Trixie) Cloud-init" || true
    grep -q 'GET vm-templates?.*filter=name_label' "$CALLS"
    run grep -c 'limit=500' "$CALLS"
    [ "$output" = "0" ]
}

@test "the build VM is created from the chosen pool's base template" {
    TPL_API_POOL_ID="pool-B"
    tpl_api_import_image() { :; }
    tpl_ssh_key_path() { echo "$S/key"; }
    tpl_build_ssh_key() { echo "ssh-ed25519 AAAA test"; }
    tpl_cloud_config() { echo "#cloud-config"; }
    tpl_api_vm_create_body() { echo "template=$2"; }
    tpl_api_post() { echo "POST $1 $2" >> "$CALLS"; return 1; }
    tpl_api_create_build_vm "x|Debian 13|trixie|https://example.invalid/i.raw|debian|tpl_prep_debian|4|bios" "Debian 13" \
        > /dev/null 2>&1 || true
    grep -qx 'POST pools/pool-B/actions/create_vm template=tpl-B' "$CALLS"
}

@test "the guest-tools ISO is the chosen pool's copy" {
    TPL_API_POOL_ID="pool-B"
    TPL_VM_UUID="vm-1"
    tpl_xo_cli() {
        echo "xo-cli $*" >> "$CALLS"
        # The by-name attempt fails, as it does on pools where the name does
        # not resolve, so the by-id lookup is what runs.
        [[ "$*" == *"cd_id=iso-"* ]]
    }
    tpl_api_attach_tools_iso > /dev/null 2>&1
    grep -q 'cd_id=iso-B' "$CALLS"
    run grep -c 'cd_id=iso-A' "$CALLS"
    [ "$output" = "0" ]
}
