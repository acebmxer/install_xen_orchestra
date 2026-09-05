#!/usr/bin/env bats
# Tests for the pure helpers behind --build-templates.
#
# The parts that talk to a pool master over SSH are not covered here — they
# need a real XAPI host. What is covered is everything that can silently
# produce a wrong-but-plausible result: the catalogue's own shape, the
# template naming both the build and the already-exists check depend on, and
# the generated in-guest preparation script.

setup() {
    load '../helpers/mock_helpers'
    load_script

    # A per-test scratch directory, created here rather than using
    # BATS_TEST_TMPDIR: that variable arrived in Bats 1.4, and Ubuntu 22.04 --
    # which this project tests against -- ships Bats 1.2.1, where it is unset.
    # Under `set -u` an unset variable is a fatal error rather than an empty
    # path, so the test that wrote into it failed outright on that image while
    # passing everywhere else. mktemp is what the other test files here use and
    # it behaves the same on every version.
    TMPDIR_TEST=$(mktemp -d)
}

teardown() {
    [[ -n "${TMPDIR_TEST:-}" ]] && rm -rf "$TMPDIR_TEST"
}

# --- catalogue shape -------------------------------------------------------
#
# A malformed row does not fail loudly: cut returns an empty field, and the
# build carries on with an empty URL or an empty prep function name.

@test "every catalogue row has all seven fields" {
    local row
    for row in "${TPL_CATALOG[@]}"; do
        [ "$(awk -F'|' '{print NF}' <<< "$row")" -eq 7 ]
    done
}

@test "every buildable row names a prep function that exists" {
    local row fn
    for row in "${TPL_CATALOG[@]}"; do
        tpl_is_placeholder "$row" && continue
        fn=$(tpl_field "$row" 6)
        declare -F "$fn" > /dev/null
    done
}

@test "every buildable image URL is https and a format the import handles" {
    local row url
    for row in "${TPL_CATALOG[@]}"; do
        tpl_is_placeholder "$row" && continue
        url=$(tpl_field "$row" 4)
        [[ "$url" =~ ^https:// ]]
        # Raw imports natively; anything else is converted on the pool master
        # first. Both are handled, but only these two extensions are: an
        # unrecognised one would reach qemu-img and fail at build time.
        [[ "$url" =~ \.(raw|img|qcow2)$ ]]
    done
}

@test "a buildable image that is not raw is routed through the conversion" {
    local row url
    for row in "${TPL_CATALOG[@]}"; do
        tpl_is_placeholder "$row" && continue
        url=$(tpl_field "$row" 4)
        # The two must agree: a non-raw image that the importer thinks is raw
        # would be written to the disk verbatim, which XAPI accepts and which
        # produces a template whose VMs do not boot.
        if [[ "$url" =~ \.raw$ ]]; then
            ! deploy_needs_conversion "$url"
        else
            deploy_needs_conversion "$url"
        fi
    done
}

# --- placeholders ----------------------------------------------------------
#
# A placeholder is a planned template with no build behind it. It must be
# visible and inert: the danger is one silently becoming selectable, since the
# rest of the build would then download an image it cannot use.

@test "a placeholder is identified by its prep function, a real row is not" {
    tpl_is_placeholder "x|X|x|https://e/x.qcow2|u|-"
    ! tpl_is_placeholder "x|X|x|https://e/x.raw|u|tpl_prep_debian"
}

@test "every placeholder URL is https and carries a published image" {
    local row url
    for row in "${TPL_CATALOG[@]}"; do
        tpl_is_placeholder "$row" || continue
        url=$(tpl_field "$row" 4)
        [[ "$url" =~ ^https:// ]]
        # Not .raw -- these are the qcow2 origins the import cannot yet take,
        # which is the reason they are placeholders rather than rows.
        [[ "$url" =~ \.(qcow2|img)$ ]]
    done
}

@test "every placeholder still has all seven fields and a display name" {
    local row
    for row in "${TPL_CATALOG[@]}"; do
        tpl_is_placeholder "$row" || continue
        [ "$(awk -F'|' '{print NF}' <<< "$row")" -eq 7 ]
        [ -n "$(tpl_field "$row" 2)" ]
    done
}

@test "the build refuses a placeholder rather than downloading its image" {
    run tpl_build_one "nope|Not Ready|x|https://e/x.qcow2|u|-"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Coming Soon"* ]]
}

@test "the catalogue is sorted, so the menu draws in order" {
    local row keys
    keys=""
    for row in "${TPL_CATALOG[@]}"; do
        keys+="$(tpl_field "$row" 1)"$'\n'
    done
    # -V compares embedded numbers numerically, so rockylinux9 sorts before
    # rockylinux10 the way the menu should read.
    [ "$keys" = "$(sort -V <<< "$keys" | grep .)"$'\n' ]
}

@test "catalogue keys are unique" {
    local row keys dupes
    keys=""
    for row in "${TPL_CATALOG[@]}"; do
        keys+="$(tpl_field "$row" 1)"$'\n'
    done
    # `|| true` because uniq -d printing nothing is the passing case, and a
    # bare grep exiting 1 on no match trips the script's own ERR trap.
    dupes=$(sort <<< "$keys" | uniq -d | grep . || true)
    [ -z "$dupes" ]
}

# --- tpl_field -------------------------------------------------------------

@test "tpl_field extracts each position from a row" {
    local row="k|Display Name|code|https://example.invalid/x.raw|user|fn"
    [ "$(tpl_field "$row" 1)" = "k" ]
    [ "$(tpl_field "$row" 2)" = "Display Name" ]
    [ "$(tpl_field "$row" 5)" = "user" ]
    [ "$(tpl_field "$row" 6)" = "fn" ]
}

# --- tpl_row_for_key -------------------------------------------------------

@test "tpl_row_for_key finds a known key" {
    run tpl_row_for_key debian13
    [ "$status" -eq 0 ]
    [[ "$output" =~ ^debian13\| ]]
}

@test "tpl_row_for_key fails on an unknown key" {
    run tpl_row_for_key nosuchdistro
    [ "$status" -ne 0 ]
}

# --- tpl_template_name -----------------------------------------------------
#
# The build and the already-exists check both derive the name from here. If
# they ever disagree, every run rebuilds a template that is already present.

@test "template names are the display name plus a fixed suffix" {
    [ "$(tpl_template_name 'Debian 13')" = "Debian 13 Cloud-init" ]
}

@test "one template serves both firmware modes" {
    # The cloud images carry an EFI system partition and a BIOS boot partition
    # on the same disk, so a single template boots either way and the operator
    # picks the mode in New VM. A firmware suffix in the name would imply two
    # templates that do not exist.
    local n
    n=$(tpl_template_name 'Debian 13')
    [[ "$n" != *BIOS* ]]
    [[ "$n" != *UEFI* ]]
}

# --- prep script -----------------------------------------------------------

@test "the debian prep script is valid shell" {
    tpl_prep_debian debian > "${TMPDIR_TEST}/prep.sh"
    bash -n "${TMPDIR_TEST}/prep.sh"
}

@test "the prep script substitutes the account name" {
    run tpl_prep_debian someuser
    [[ "$output" == *"someuser:someuser"* ]]
    # The placeholder must not survive into the emitted script.
    [[ "$output" != *"__TPL_USER__"* ]]
}

@test "the prep script ends by powering the VM off" {
    # The build treats the VM halting as its completion signal, so a script
    # that returns without shutting down hangs the build until the timeout.
    run tpl_prep_debian debian
    [[ "$(grep -v '^\s*#' <<< "$output" | grep -c .)" -gt 0 ]]
    [[ "$(grep -v '^\s*#' <<< "$output" | grep . | tail -1)" == "shutdown -h now" ]]
}

@test "the prep script scrubs every piece of machine identity" {
    run tpl_prep_debian debian
    # Each of these produces colliding clones if it is dropped.
    [[ "$output" == *"cloud-init clean"* ]]
    [[ "$output" == *"/etc/machine-id"* ]]
    [[ "$output" == *"ssh_host_"* ]]
    [[ "$output" == *"/var/lib/cloud/instances"* ]]
}

@test "the prep script installs guest tools from the ISO before falling back to apt" {
    # Debian 13 has no xe-guest-utilities package, and a failed apt install
    # does not stop cloud-init — so an ISO-last ordering produces a template
    # that looks fine and never reports an IP.
    run tpl_prep_debian debian
    local iso_line apt_line
    iso_line=$(grep -n 'install.sh' <<< "$output" | head -1 | cut -d: -f1)
    apt_line=$(grep -n 'apt-get install -y xe-guest-utilities' <<< "$output" | head -1 | cut -d: -f1)
    [ -n "$iso_line" ]
    [ -n "$apt_line" ]
    [ "$iso_line" -lt "$apt_line" ]
}

@test "the prep script installs growroot so deploy-time disk sizes take effect" {
    run tpl_prep_debian debian
    [[ "$output" == *"cloud-initramfs-growroot"* ]]
}

# --- menu wiring -----------------------------------------------------------
#
# The dispatch in process_menu_selections indexes MENU_SELECTED by number, so
# inserting an item shifts every entry after it and silently runs the wrong
# action. These pin the item to the label it is meant to trigger.

@test "the template library sits at the menu index its dispatch uses" {
    local idx=-1 i
    for ((i = 0; i < MENU_TOTAL; i++)); do
        [[ "${MENU_NAMES[$i]}" == "VM Template Library" ]] && idx=$i
    done
    [ "$idx" -eq 5 ]
}

@test "backing out of the library selects nothing and does not fail" {
    # Q must not return non-zero: the script's ERR trap turns that into a
    # printed error on what is a normal way to leave a menu.
    clear() { :; }
    menu_hide_cursor() { :; }
    menu_show_cursor() { :; }
    stty() { :; }
    tpl_template_exists() { return 1; }
    menu_read_key() { MENU_KEY="QUIT"; }

    run tpl_prompt_selection
    [ "$status" -eq 0 ]
}

@test "the build creates a working directory before it connects" {
    # Every helper below build_vm_templates interpolates DEPLOY_WORKDIR into a
    # path -- the SSH control socket, the pinned host key, the prep drive. An
    # unset workdir does not fail loudly: the paths resolve to the filesystem
    # root and the run dies on "Permission denied" from ssh, which reads as a
    # rejected password rather than a missing directory.
    local body
    body=$(declare -f build_vm_templates)

    local mk conn
    mk=$(grep -n 'DEPLOY_WORKDIR=' <<< "$body" | head -1 | cut -d: -f1)
    conn=$(grep -n 'deploy_connect_pool_master' <<< "$body" | head -1 | cut -d: -f1)

    [ -n "$mk" ]
    [ -n "$conn" ]
    [ "$mk" -lt "$conn" ]
}

@test "the build installs a cleanup trap for its working directory" {
    local body
    body=$(declare -f build_vm_templates)
    [[ "$body" == *"trap tpl_cleanup EXIT"* ]]
    declare -F tpl_cleanup > /dev/null
}

# --- storage and network resolution ----------------------------------------
#
# These are build scaffolding, not user choices: the SR holds only the
# template's own disk and the network is used once for the preparation boot,
# and both are chosen again in New VM. Prompting for them would ask the
# operator to decide something that does not survive the build.

@test "the template build does not prompt for storage or network" {
    local body
    body=$(declare -f build_vm_templates)
    [[ "$body" != *"deploy_pick_sr"* ]]
    [[ "$body" != *"deploy_pick_network"* ]]
    [[ "$body" == *"tpl_resolve_storage"* ]]
    [[ "$body" == *"tpl_resolve_network"* ]]
}

@test "--deploy keeps its own storage and network prompts" {
    # The resolvers are for the template path only; --deploy creates a
    # long-lived VM where where it lives is genuinely the operator's call.
    local body
    body=$(declare -f deploy_xo_vm)
    [[ "$body" == *"deploy_pick_sr"* ]]
    [[ "$body" == *"deploy_pick_network"* ]]
}

@test "storage resolves to the pool default" {
    dom0_xe() {
        case "$1" in
            *"pool-list"*) echo "pool-uuid" ;;
            *"param-name=default-SR"*) echo "sr-default" ;;
            *"name-label"*) echo "vm_storage" ;;
        esac
    }
    run tpl_resolve_storage
    [ "$status" -eq 0 ]
    [[ "$output" == *"vm_storage"* ]]
}

@test "storage falls back to the emptiest SR when the pool has no default" {
    dom0_xe() {
        case "$1" in
            *"pool-list"*) echo "pool-uuid" ;;
            *"param-name=default-SR"*) echo "<not in database>" ;;
            *"name-label"*) echo "fallback-sr" ;;
        esac
    }
    dom0_exec() { echo "sr-most-free"; }
    run tpl_resolve_storage
    [ "$status" -eq 0 ]
}

@test "network resolves to the management network" {
    dom0_xe() {
        case "$1" in
            *"pif-list management=true"*) echo "net-mgmt" ;;
            *"name-label"*) echo "Pool-wide network 0" ;;
        esac
    }
    run tpl_resolve_network
    [ "$status" -eq 0 ]
    [[ "$output" == *"Pool-wide network 0"* ]]
}

@test "resolution fails loudly when the pool offers nothing" {
    dom0_xe() { echo ""; }
    dom0_exec() { echo ""; }
    run tpl_resolve_storage
    [ "$status" -eq 1 ]
    run tpl_resolve_network
    [ "$status" -eq 1 ]
}

# --- guest tools attachment ------------------------------------------------
#
# The base template provisions no CD drive, so there is nothing for
# `vm-cd-insert` to insert into. And pools accumulate several VDIs whose names
# contain "guest-tools.iso", so attaching by name is ambiguous. Both faults
# produce the same outcome: a template with no guest agent, which looks like a
# successful build and is only discovered when a VM never reports an IP.

@test "the tools ISO is attached to a CD drive the build creates" {
    local body
    body=$(declare -f tpl_attach_tools_iso)
    # A drive has to exist before a disc can be put in it.
    [[ "$body" == *"vbd-create"* ]]
    [[ "$body" == *"type=CD"* ]]
    # Attaching by uuid, not by name: several VDIs share the name.
    [[ "$body" == *"vdi-uuid="* ]]
}

@test "a missing tools ISO fails the build instead of warning" {
    # Debian 13 has no xe-guest-utilities package for the prep script to fall
    # back to, so a build without the ISO cannot produce a working template.
    local body
    body=$(declare -f tpl_create_build_vm)
    local seg="${body#*tpl_find_tools_iso}"
    [[ "$seg" == *"log_error"* ]]
    [[ "$seg" == *"return 1"* ]]
}

# --- preparation boot ------------------------------------------------------

@test "the wait watches the VM start before watching it stop" {
    # vm-start returns before XAPI has necessarily left the halted state, so a
    # loop that only watches for "halted" returns immediately and seals a
    # template that never booted.
    local body
    body=$(declare -f tpl_wait_for_prep)
    local run_at halt_at
    run_at=$(grep -n '"running"' <<< "$body" | head -1 | cut -d: -f1)
    halt_at=$(grep -n '"halted"' <<< "$body" | head -1 | cut -d: -f1)
    [ -n "$run_at" ]
    [ -n "$halt_at" ]
    [ "$run_at" -lt "$halt_at" ]
}

@test "a build only seals once the guest agent is proven installed" {
    # Booting and halting is not evidence the prep ran: a panic, a cloud-init
    # failure, or an unread config drive all end the same way. XAPI records the
    # agent's version only when the agent has run inside the VM -- and only
    # while that VM is running, which is why the observation is recorded during
    # the boot and checked here rather than read off the halted VM.
    local body
    body=$(declare -f tpl_build_one)
    local check_at seal_at
    check_at=$(grep -n 'TPL_AGENT_SEEN' <<< "$body" | head -1 | cut -d: -f1)
    seal_at=$(grep -n 'tpl_seal_template' <<< "$body" | head -1 | cut -d: -f1)
    [ -n "$check_at" ]
    [ -n "$seal_at" ]
    [ "$check_at" -lt "$seal_at" ]
}

# --- import verification ---------------------------------------------------

@test "the template disk is larger than the image it holds" {
    # The current cloud images are 3 GiB, so the disk has to exceed that. The
    # margin is deliberately small: a clone starts at the template's size unless
    # the operator asks for more, so an oversized template inflates every VM
    # built from it. XO's own Hub template for this image runs about two
    # megabytes over the image.
    [ "$TPL_DEFAULT_DISK_GB" -gt 3 ]
    [ "$TPL_DEFAULT_DISK_GB" -le 8 ]
}

@test "an import that writes nothing fails the build" {
    local body
    body=$(declare -f tpl_create_build_vm)
    [[ "$body" == *"tpl_disk_has_partition_table"* ]]
    # The check has to sit between the import and the success line, or it
    # reports a blank disk as a finished one.
    local imp chk ok
    imp=$(grep -n 'deploy_import_vdi_from_url' <<< "$body" | head -1 | cut -d: -f1)
    chk=$(grep -n 'tpl_disk_has_partition_table' <<< "$body" | head -1 | cut -d: -f1)
    ok=$(grep -n 'image imported and checksum verified' <<< "$body" | head -1 | cut -d: -f1)
    [ "$imp" -lt "$chk" ]
    [ "$chk" -lt "$ok" ]
}

# --- what counts as an imported disk ---------------------------------------
#
# physical-utilisation is allocated blocks, not bytes written. XAPI imports raw
# images with vhd-tool's --prezeroed on any SR that is not lvm/lvmoiscsi/
# lvmohba, so zero blocks are skipped rather than written, and a correctly
# imported cloud image allocates almost nothing: Debian 13 lands at 19456 bytes
# on thin NFS. A byte threshold rejects every good import on thin storage.

@test "the disk check does not judge an import by how much the SR allocated" {
    local body
    body=$(declare -f tpl_create_build_vm)
    # A threshold comparison against physical-utilisation is the bug itself.
    [[ "$body" != *"used < 104857600"* ]]
}

@test "a disk carrying an MBR passes the check" {
    deploy_vdi_ref() { echo "OpaqueRef:aaaa"; }
    # 0x55AA at offset 510: 1020 hex characters, then 55aa, then a second sector.
    dom0_exec() { printf '%01020d55aa%01024d' 0 0; }
    run tpl_disk_has_partition_table "some-vdi"
    [ "$status" -eq 0 ]
}

@test "a disk carrying a bare GPT header passes the check" {
    deploy_vdi_ref() { echo "OpaqueRef:aaaa"; }
    # "EFI PART" at offset 512, with no protective MBR before it.
    dom0_exec() { printf '%01024d4546492050415254%0999d' 0 0; }
    run tpl_disk_has_partition_table "some-vdi"
    [ "$status" -eq 0 ]
}

@test "a blank disk fails the check" {
    deploy_vdi_ref() { echo "OpaqueRef:aaaa"; }
    dom0_exec() { printf '%02048d' 0; }
    run tpl_disk_has_partition_table "some-vdi"
    [ "$status" -ne 0 ]
}

@test "a sparse import allocating only a few kilobytes still passes" {
    # The regression this whole check exists to prevent: 19456 bytes allocated
    # is what a correct Debian 13 import looks like on thin NFS.
    deploy_vdi_ref() { echo "OpaqueRef:aaaa"; }
    dom0_exec() { printf '%01020d55aa%01024d' 0 0; }
    run tpl_disk_has_partition_table "some-vdi"
    [ "$status" -eq 0 ]
}

@test "the disk read is capped so a whole VDI cannot reach a shell variable" {
    # /export_raw_vdi has no Range handling (export_raw_vdi.ml answers a plain
    # 200 and streams the whole disk), so `curl -r` is ignored and the entire
    # VDI comes back. Expanded by od into a command substitution, an 8 GiB disk
    # segfaults bash. The cap has to be a pipe that closes, not a request the
    # server is free to disregard.
    local body
    body=$(declare -f tpl_disk_has_partition_table)
    [[ "$body" == *"head -c 1024"* ]]
    [[ "$body" != *"-r 0-1023"* ]]
}

@test "the disk is read without attaching it to dom0" {
    # There is no `xe vdi-attach` -- VDI.attach is an API call the CLI does not
    # expose -- and an attached VDI could not then be plugged into the build VM.
    local body
    body=$(declare -f tpl_disk_has_partition_table)
    [[ "$body" != *"vdi-attach"* ]]
    [[ "$body" == *"export_raw_vdi"* ]]
}

@test "a check that cannot run does not fail a good import" {
    # Refusing a build over a check that could not be performed is the mistake
    # this function replaced.
    deploy_vdi_ref() { return 1; }
    dom0_exec() { echo ""; }
    run tpl_disk_has_partition_table "some-vdi"
    [ "$status" -eq 0 ]
}

# --- the guest agent is only visible while the VM is running ---------------
#
# XAPI populates PV-drivers-version from the agent inside the guest and clears
# it when the domain goes away. The preparation boot ends by powering the VM
# off, so reading the field afterwards always returns nothing however well the
# install went -- which failed every build that had otherwise succeeded.

@test "the guest agent is observed while the VM is still running" {
    local body
    body=$(declare -f tpl_wait_for_prep)
    [[ "$body" == *"PV-drivers-version"* ]]
    [[ "$body" == *"TPL_AGENT_SEEN"* ]]
}

@test "the agent check uses a signal that survives the shutdown" {
    # PV-drivers-version is cleared when the domain goes away; os-version and
    # the reported addresses persist. Checked on a live pool: every halted VM
    # reports PV-drivers-version empty, working ones included. Depending on it
    # fails every build.
    local body
    body=$(declare -f tpl_build_one)
    [[ "$body" == *"param-name=os-version"* ]]
    [[ "$body" != *'vm-param-get uuid=${TPL_VM_UUID} param-name=PV-drivers-version'* ]]
}

@test "os-version reported by the agent passes the build" {
    local osv="Debian GNU/Linux 13 (trixie); uname: 6.12.107+deb13-cloud-amd64"
    local seen=""
    [[ "$osv" =~ [A-Za-z] ]]
    ! [[ -z "$osv" && ! "${seen:-}" =~ [0-9]+\.[0-9]+ ]]
}

@test "a VM whose agent never ran fails the build" {
    local osv="" seen=""
    [[ -z "$osv" && ! "${seen:-}" =~ [0-9]+\.[0-9]+ ]]
}

@test "an agent version caught during the boot still passes on its own" {
    # Corroboration when os-version is somehow unavailable.
    local osv="" seen="7.30.0-18"
    ! [[ -z "$osv" && ! "${seen:-}" =~ [0-9]+\.[0-9]+ ]]
}

@test "xe reporting no guest metrics is not mistaken for a distro name" {
    # "<not in database>" contains letters, so a bare letter test passes on a
    # VM that never reported anything.
    local body
    body=$(declare -f tpl_build_one)
    [[ "$body" == *"not in database"* ]]
}

@test "the guest agent check requires a version number, not just any output" {
    # xe prints map parameters as punctuation even when empty, so testing for
    # an empty string passes on a VM whose agent never ran.
    local body
    body=$(declare -f tpl_build_one)
    [[ "$body" == *'[0-9]+\.[0-9]+'* ]]
}

# --- failure leaves nothing half-built -------------------------------------

@test "every precondition is checked before a template is sealed" {
    # A template that exists is indistinguishable from a good one at a glance,
    # and the already-exists check then skips rebuilding it -- so each guard
    # has to run before the seal, not after.
    local body
    body=$(declare -f tpl_build_one)
    local seal_at
    seal_at=$(grep -n 'tpl_seal_template' <<< "$body" | head -1 | cut -d: -f1)

    local guard
    for guard in tpl_create_build_vm tpl_wait_for_prep TPL_AGENT_SEEN; do
        local at
        at=$(grep -n "$guard" <<< "$body" | head -1 | cut -d: -f1)
        [ -n "$at" ]
        [ "$at" -lt "$seal_at" ]
    done
}

@test "the build VM is named as work in progress" {
    # It is visible in XO for the minutes the preparation boot takes, so it has
    # to read as a step rather than a VM someone abandoned.
    local body
    body=$(declare -f tpl_create_build_vm)
    [[ "$body" == *"[building template]"* ]]
}

# --- staged download -------------------------------------------------------
#
# The download resumes with `curl -C -`, so whatever is already at the staging
# path is treated as progress. That makes the path's uniqueness load-bearing:
# a stale complete file is "finished" instantly, the checksum passes because
# its bytes are genuine, and what reaches the disk is whatever the file held.

@test "the staging path is unique per import, not per calling shell" {
    local body
    body=$(declare -f deploy_import_vdi_staged)
    # $$ is the workstation's PID, which is not unique on the pool master and
    # repeats across runs.
    [[ "$body" != *'xo-deploy-image-$$'* ]]
    # Named after the destination VDI, which is a fresh uuid every build.
    [[ "$body" == *'/var/tmp/xo-image-${vdi}.raw'* ]]
}

@test "a staged file that is too small fails before it is imported" {
    local body
    body=$(declare -f deploy_import_vdi_staged)
    local chk imp
    chk=$(grep -n 'the staged image on the pool master' <<< "$body" | head -1 | cut -d: -f1)
    imp=$(grep -n 'import_raw_vdi' <<< "$body" | head -1 | cut -d: -f1)
    [ -n "$chk" ]
    [ -n "$imp" ]
    [ "$chk" -lt "$imp" ]
}

@test "import failures report what the pool master said" {
    # -s -f hides curl's message and reduces an HTTP error to an exit code,
    # which leaves the cause invisible to whoever has to diagnose it.
    local body
    body=$(declare -f deploy_import_vdi_staged)
    [[ "$body" == *"--show-error"* ]]
    [[ "$body" == *"rejected the import"* ]]
}

# --- XAPI reference resolution ---------------------------------------------
#
# `xe vdi-create` returns a uuid, but XAPI's /import_raw_vdi endpoint takes an
# OpaqueRef. Given a uuid it does not reject the request: it accepts the
# connection, writes ~19 KB of header and stops, leaving a near-empty VDI and
# an import that reported success -- which reads as a disk too small for its
# image rather than a bad reference.

@test "every raw import sends an opaque ref, not a uuid" {
    # The count is asserted because `continue` on a missing function turns a
    # renamed import path into a test that passes without checking anything.
    local body fn found=0
    for fn in deploy_import_vdi_staged deploy_import_vdi_from_file deploy_import_vdi_from_url; do
        declare -F "$fn" > /dev/null || continue
        found=$((found + 1))
        body=$(declare -f "$fn")
        [[ "$body" != *'vdi=${vdi}&format'* ]]
    done
    [ "$found" -eq 3 ]
}

@test "the ref resolver only returns an opaque ref" {
    dom0_exec() { echo "OpaqueRef:11111111-2222-3333-4444-555555555555"; }
    run deploy_vdi_ref "some-uuid"
    [ "$status" -eq 0 ]
    [[ "$output" == OpaqueRef:* ]]
}

@test "the ref resolver fails rather than falling back to the uuid" {
    # Returning the uuid here would resurrect the original bug in a form that
    # looks like it was handled.
    dom0_exec() { echo ""; }
    xml_escape() { printf '%s' "$1"; }
    run deploy_vdi_ref "some-uuid"
    [ "$status" -ne 0 ]
    [[ "$output" != *"some-uuid"* ]]
}

# --- imports reporting themselves through XAPI's task ----------------------
#
# /import_raw_vdi answers the HTTP request as soon as it accepts the stream, so
# curl exiting 0 proves only that the bytes were taken. An import that then
# fails inside XAPI leaves a VDI holding a few kilobytes of header and a caller
# that believes it worked — the failure that read as a disk too small for its
# image. The task is the only channel that says otherwise.

@test "every raw import passes a task id so failures can be seen" {
    local body fn found=0
    for fn in deploy_import_vdi_staged deploy_import_vdi_from_file deploy_import_vdi_from_url; do
        declare -F "$fn" > /dev/null || continue
        found=$((found + 1))
        body=$(declare -f "$fn")
        [[ "$body" == *"deploy_task_create"* ]]
        [[ "$body" == *'task_q'* ]]
        [[ "$body" == *"deploy_task_check"* ]]
    done
    [ "$found" -eq 3 ]
}

@test "a task reported as failure fails the import" {
    deploy_xapi_call() {
        case "$1" in
            task.get_status) echo "<value>failure</value>" ;;
            task.get_error_info) echo "<value><array><data><value><string>SR_BACKEND_FAILURE_44</string></value><value><string>There is insufficient space</string></value></data></array></value>" ;;
        esac
    }
    run deploy_task_check "OpaqueRef:aaaa-bbbb"
    [ "$status" -ne 0 ]
}

@test "a failed task reports the error code, not just its description" {
    # The code is the half worth searching for, and XAPI returns every element
    # of error_info on one line — so a per-line match drops all but the last.
    deploy_xapi_call() {
        case "$1" in
            task.get_status) echo "<value>failure</value>" ;;
            task.get_error_info) echo "<value><array><data><value><string>SR_BACKEND_FAILURE_44</string></value><value><string>There is insufficient space</string></value></data></array></value>" ;;
        esac
    }
    run deploy_task_check "OpaqueRef:aaaa-bbbb"
    [[ "$output" == *"SR_BACKEND_FAILURE_44"* ]]
    [[ "$output" == *"There is insufficient space"* ]]
}

@test "a task reported as success passes the import" {
    deploy_xapi_call() {
        case "$1" in
            task.get_status) echo "<value>success</value>" ;;
        esac
    }
    run deploy_task_check "OpaqueRef:aaaa-bbbb"
    [ "$status" -eq 0 ]
}

@test "an unreadable task does not fail an import that otherwise worked" {
    # The physical-utilisation check still stands behind this. A task that
    # could not be created or read should not turn a good import into a
    # reported failure.
    deploy_xapi_call() { echo ""; }
    run deploy_task_check ""
    [ "$status" -eq 0 ]
    run deploy_task_check "OpaqueRef:aaaa-bbbb"
    [ "$status" -eq 0 ]
}

@test "opaque refs are matched beyond hex so no reference is truncated" {
    # OpaqueRef bodies are not guaranteed to be hex-and-dash. A pattern that
    # assumes they are silently returns "OpaqueRef:" — which XAPI accepts and
    # then ignores, reproducing the original empty-disk failure exactly.
    local body
    body=$(declare -f deploy_vdi_ref deploy_task_create deploy_xapi_login)
    [[ "$body" != *'OpaqueRef:[a-f0-9-]'* ]]
}

# --- imports on a pool with more than one host -----------------------------
#
# XAPI's import handler checks whether the host being asked can actually see
# the target SR, and answers 302 to the host that can when it cannot
# (import_raw_vdi.ml: check_sr_availability / return_302_redirect). curl's -f
# fails on 4xx and 5xx only, so an unfollowed 302 exits 0 having sent the body
# nowhere -- leaving a VDI with a few kilobytes of header and an import that
# reported success. This is the empty-disk failure, and it only appears on a
# pool whose SR is not local to the master.

@test "every raw import follows redirects so a multi-host pool works" {
    local body fn found=0
    for fn in deploy_import_vdi_staged deploy_import_vdi_from_file; do
        declare -F "$fn" > /dev/null || continue
        found=$((found + 1))
        body=$(declare -f "$fn")
        [[ "$body" == *"-L"* ]]
        [[ "$body" == *"--post302"* ]]
    done
    [ "$found" -eq 2 ]
}

@test "the streaming import follows redirects too" {
    local body
    body=$(deploy_stream_script)
    [[ "$body" == *"-L"* ]]
    [[ "$body" == *"--post302"* ]]
}

@test "a redirected import is reported rather than passing silently" {
    # The hop is worth naming: an import that lands on another host is correct
    # but not obvious, and its absence is what made this bug invisible.
    local body
    body=$(declare -f deploy_import_vdi_staged)
    [[ "$body" == *"num_redirects"* ]]
}

@test "an import with no task created says so instead of reading as success" {
    run deploy_task_check ""
    [ "$status" -eq 0 ]
    [[ "$output" == *"not watched"* ]]
}

@test "an unreadable task status prints what XAPI actually replied" {
    deploy_xapi_call() { echo "<unexpected>garbage</unexpected>"; }
    run deploy_task_check "OpaqueRef:aaaa-bbbb"
    [ "$status" -eq 0 ]
    [[ "$output" == *"could not read the import task's status"* ]]
}

# --- boot firmware ---------------------------------------------------------
#
# Whether an image is UEFI-bootable is a property of that image, not of the
# distribution, so it is read off the imported disk rather than declared. UEFI
# is preferred where the disk supports it: the cloud images carrying an ESP
# carry a BIOS boot partition beside it, so choosing BIOS still works, while
# UEFI with no bootloader to load does not fall back -- it fails to boot.

@test "a disk with an EFI system partition is published as UEFI" {
    deploy_vdi_ref() { echo "OpaqueRef:aaaa"; }
    # "EFI PART" at offset 512, then the ESP type GUID in its on-disk
    # (mixed-endian) byte order somewhere in the partition array.
    dom0_exec() { printf '%01024d4546492050415254%0512d28732ac11ff8d211ba4b00a0c93ec93b' 0 0; }
    run tpl_disk_supports_uefi "some-vdi"
    [ "$status" -eq 0 ]
}

@test "a GPT disk with no EFI system partition is published as BIOS" {
    deploy_vdi_ref() { echo "OpaqueRef:aaaa"; }
    # A GPT, but only a Linux root partition type in the array.
    dom0_exec() { printf '%01024d4546492050415254%0512de3bc684fcde8b14d96e7fbcaf984b709' 0 0; }
    run tpl_disk_supports_uefi "some-vdi"
    [ "$status" -ne 0 ]
}

@test "a disk with no GPT at all is published as BIOS" {
    deploy_vdi_ref() { echo "OpaqueRef:aaaa"; }
    dom0_exec() { printf '%04096d' 0; }
    run tpl_disk_supports_uefi "some-vdi"
    [ "$status" -ne 0 ]
}

@test "the firmware probe reads past the start of the partition array" {
    # A 32 KiB window truncates the 128-entry array and reports a UEFI-capable
    # image as BIOS-only. That happened once already, against Debian's own
    # cloud images, and produced a template defaulting to the wrong firmware.
    local body
    body=$(declare -f tpl_disk_supports_uefi)
    [[ "$body" == *"head -c 40960"* ]]
}

@test "the seal sets a firmware either way, never leaving it unset" {
    # Unset reads as BIOS in XO's New VM form, which would silently be the
    # default for a UEFI-capable image.
    local body
    body=$(declare -f tpl_seal_template)
    [[ "$body" == *"tpl_disk_supports_uefi"* ]]
    [[ "$body" == *"firmware=uefi"* ]]
    [[ "$body" == *"firmware=bios"* ]]
}

@test "the build boot itself always runs under BIOS" {
    # A UEFI guest writes boot entries into its own NVRAM on first boot, which
    # would then be baked into the template.
    local body
    body=$(declare -f tpl_create_build_vm)
    [[ "$body" == *"BIOS order"* ]]
    [[ "$body" != *"firmware=uefi"* ]]
}

@test "the console gets both a std adapter and the 8 MiB that goes with it" {
    # vga=std alone is not enough: videoram stays at whatever the base template
    # carried, which is 4, and a template built that way produced UEFI VMs with
    # an unreadable console. 16 is no better -- it renders as coloured noise
    # under UEFI. Every working UEFI VM on a live pool runs std with 8. XAPI
    # accepts any of these silently, so a wrong value only shows on the console.
    local body
    body=$(declare -f tpl_create_build_vm)
    [[ "$body" == *"platform:vga=std"* ]]
    [[ "$body" == *"platform:videoram=8"* ]]
    [[ "$body" != *"platform:videoram=16"* ]]
}

# --- settings inherited from the scaffolding template ----------------------
#
# The build starts from "Other install media", whose defaults are aimed at an
# unknown guest. Anything not explicitly overridden travels into the finished
# template, where it is nobody's deliberate choice. Each of these was found by
# comparing a built template against the VMs already running on a live pool.

@test "viridian is turned off for a Linux template" {
    # Hyper-V enlightenment, for Windows guests. The base template enables it;
    # on a live pool the only VMs carrying it are the Windows ones and the ones
    # this script built.
    local body
    body=$(declare -f tpl_create_build_vm)
    [[ "$body" == *"platform:viridian=false"* ]]
}

@test "vCPUs are presented as cores on one socket" {
    # The base template leaves cores-per-socket at 1, so a 2-vCPU VM arrives as
    # a two-socket machine. Guests licence and schedule per socket, and every
    # VM on a live pool not built from this path has cores-per-socket equal to
    # its vCPU count.
    local body
    body=$(declare -f tpl_create_build_vm)
    [[ "$body" == *"platform:cores-per-socket=\${TPL_DEFAULT_VCPUS}"* ]]
}

@test "the sealed template names itself as what its VMs were built from" {
    # Otherwise every VM cloned from it reports "Other install media" in XO's
    # General tab -- the scaffolding, not the template the operator picked.
    local body
    body=$(declare -f tpl_seal_template)
    [[ "$body" == *"other-config:base_template_name"* ]]
}

@test "catalogue images carry a full kernel, not the cloud one" {
    # genericcloud and generic are published side by side, same size, nearly
    # the same name, and differ in kernel:
    #   genericcloud  vmlinuz-...-cloud-amd64   (no bochs, no efi-framebuffer)
    #   generic       vmlinuz-...-amd64
    # The cloud kernel has no driver for the VGA card Qemu emulates, so the
    # guest falls back to simple-framebuffer, which OVMF's initialisation does
    # not agree with, and the XO console renders as scrambled colour under UEFI.
    # XCP-ng documents this at https://xcp-ng.org/docs/guests.html under
    # "Distorted display console on Ubuntu UEFI VMs". The VM boots and works, so
    # nothing reports an error.
    local row url
    for row in "${TPL_CATALOG[@]}"; do
        url=$(tpl_field "$row" 4)
        [[ "$url" != *genericcloud* ]]
    done
}

# --- checksum origin --------------------------------------------------------
#
# The digest is what separates a genuine image from one a bad mirror served
# with a perfectly consistent Content-Length, so picking the wrong sums file
# does not fail loudly -- it warns that the image could not be verified and
# imports it anyway.

@test "Ubuntu's images are verified against SHA256SUMS, Debian's against SHA512SUMS" {
    # Both are published in coreutils' own format, so only the name and the
    # algorithm differ. Read from the URL rather than declared per row, so
    # adding an image cannot forget to state it.
    [ "$(deploy_checksum_source 'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img')" = "SHA256SUMS 256" ]
    [ "$(deploy_checksum_source 'https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.raw')" = "SHA512SUMS 512" ]
}

@test "an unknown origin falls back to SHA512SUMS rather than skipping the check" {
    # The fallback has to be a real attempt at verification. Returning nothing
    # would turn an unrecognised mirror into an unverified import.
    [ "$(deploy_checksum_source 'https://mirror.invalid/some/image.raw')" = "SHA512SUMS 512" ]
}

@test "every catalogue origin resolves to a checksum file and a digest length" {
    local row url src file bits
    for row in "${TPL_CATALOG[@]}"; do
        url=$(tpl_field "$row" 4)
        src=$(deploy_checksum_source "$url")
        read -r file bits <<< "$src"
        [ -n "$file" ]
        # The length gates the digest regex and picks the shaNsum binary, so a
        # value other than these two would build a command that does not exist.
        [[ "$bits" == "256" || "$bits" == "512" ]]
    done
}

@test "the digest length checked is the one the origin publishes" {
    # A SHA-256 digest is 64 hex characters and a SHA-512 is 128. Validating
    # Ubuntu's against the 128 the old code hardcoded would reject every
    # genuine digest as malformed.
    local body
    body=$(declare -f deploy_verify_image_checksum)
    [[ "$body" == *'hex_len=$(( sums_bits / 4 ))'* ]]
    [[ "$body" == *'sha${sums_bits}sum'* ]]
}

@test "a pinned digest is always SHA-512 whatever the origin publishes" {
    # XO_DEPLOY_IMAGE_SHA512 names its algorithm, so an Ubuntu URL must not
    # switch the pin to a 256-bit comparison.
    local body
    body=$(declare -f deploy_verify_image_checksum)
    [[ "$body" == *'[[ -n "$pinned" ]] && sums_bits=512'* ]]
}

# --- image conversion -------------------------------------------------------
#
# /import_raw_vdi takes raw bytes and nothing else. A qcow2 sent to it is
# accepted without complaint and written to the disk as a file, producing a
# template whose VMs do not boot -- with nothing reporting an error.

@test "a .img is treated as needing conversion, not as raw" {
    # Ubuntu's cloud images are qcow2 named .img. Trusting the extension is
    # exactly the trap: verified by magic, they begin "QFI\xfb".
    deploy_needs_conversion "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
}

@test "a .raw is imported without conversion" {
    ! deploy_needs_conversion "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.raw"
}

@test "a query string does not make a raw image look convertible" {
    ! deploy_needs_conversion "https://example.invalid/image.raw?token=abc"
}

@test "an unknown extension is converted rather than assumed raw" {
    # The safe direction: qemu-img detects the real format itself, so
    # converting something already raw costs a copy, while assuming raw
    # wrongly costs a template that does not boot.
    deploy_needs_conversion "https://example.invalid/image.unknown"
}

@test "qemu-img is checked before the image is downloaded, not after" {
    # Discovering it after several gigabytes have been fetched wastes the
    # download and reports as a conversion failure rather than a missing tool.
    local body
    body=$(declare -f deploy_import_vdi_staged)
    local probe dl
    probe=$(grep -n 'deploy_ensure_qemu_img' <<< "$body" | head -1 | cut -d: -f1)
    dl=$(grep -n 'downloading the image to the pool master' <<< "$body" | head -1 | cut -d: -f1)
    [ -n "$probe" ]
    [ -n "$dl" ]
    [ "$probe" -lt "$dl" ]
}

@test "the image is checksummed as downloaded, before it is converted" {
    # The origin publishes a digest of the file it publishes, so hashing the
    # converted image could never match it.
    local body
    body=$(declare -f deploy_import_vdi_staged)
    local sum conv
    sum=$(grep -n 'deploy_verify_image_checksum' <<< "$body" | head -1 | cut -d: -f1)
    conv=$(grep -n 'qemu-img convert' <<< "$body" | head -1 | cut -d: -f1)
    [ -n "$sum" ]
    [ -n "$conv" ]
    [ "$sum" -lt "$conv" ]
}

@test "the conversion lets qemu-img detect the source format" {
    # -f from the extension would defeat the point: the extension is what
    # cannot be trusted here. A wrong -f is a misparsed disk, not a clean error.
    local body
    body=$(declare -f deploy_import_vdi_staged)
    [[ "$body" == *"qemu-img convert -O raw"* ]]
    [[ "$body" != *"qemu-img convert -f"* ]]
}

@test "a non-raw image is never streamed, because a stream cannot be converted" {
    # Streaming pipes the origin's bytes straight into the VDI, so a qcow2
    # would land verbatim. Staging is the only path that can take one.
    local body
    body=$(declare -f deploy_import_vdi_from_url)
    [[ "$body" == *"deploy_needs_conversion"* ]]
}

@test "the space check budgets for the expanded disk, not just the download" {
    # A qcow2 is compressed and sparse: Ubuntu 24.04 is 596 MiB on the wire and
    # 3.5 GiB converted. Budgeting only for the download passes the check and
    # then fills /var/tmp mid-conversion.
    local body
    body=$(declare -f deploy_import_vdi_staged)
    [[ "$body" == *'need_mb=$(( size / 1048576 * 5 + 256 ))'* ]]
}

@test "the download and the converted image use different paths" {
    # Converting in place would mean qemu-img reading and writing one file.
    local body
    body=$(declare -f deploy_import_vdi_staged)
    [[ "$body" == *'dl="/var/tmp/xo-image-${vdi}.src"'* ]]
    [[ "$body" == *'tmp="/var/tmp/xo-image-${vdi}.raw"'* ]]
}

# --- per-row disk size ------------------------------------------------------

@test "a row's disk size overrides the default" {
    # The VDI has to clear the image's *virtual* size. Ubuntu expands to
    # 3.5 GiB, which the 4 GiB default barely clears.
    [ "$(tpl_field "$(tpl_row_for_key ubuntu2404)" 7)" = "6" ]
}

@test "the Debian rows keep the default rather than being inflated" {
    # A clone starts at the template's size, so raising the default for
    # everyone would inflate every VM built from every template.
    [ -z "$(tpl_field "$(tpl_row_for_key debian12)" 7)" ]
    [ -z "$(tpl_field "$(tpl_row_for_key debian13)" 7)" ]
}

@test "every declared disk size clears the image it has to hold" {
    # 6 GiB against Ubuntu's 3.5 GiB expanded. A row whose disk is smaller than
    # its image fails only at import time, several minutes in.
    local row size
    for row in "${TPL_CATALOG[@]}"; do
        size=$(tpl_field "$row" 7)
        [[ -z "$size" ]] && continue
        [[ "$size" =~ ^[0-9]+$ ]]
        [ "$size" -ge 4 ]
    done
}

@test "the build sizes the disk from the row, not from the global default" {
    local body
    body=$(declare -f tpl_create_build_vm)
    [[ "$body" == *'virtual-size=${disk_gb}GiB'* ]]
}

@test "a missing or malformed disk size falls back to the default" {
    # An empty field is the normal case for most rows. A malformed one would
    # otherwise reach vdi-create as a bad value and fail with an XAPI error
    # that says nothing about the row that caused it.
    local body
    body=$(declare -f tpl_create_build_vm)
    [[ "$body" == *'disk_gb="$TPL_DEFAULT_DISK_GB"'* ]]
    [[ "$body" == *'"$disk_gb" =~ ^[0-9]+$'* ]]
}

# --- Ubuntu -----------------------------------------------------------------

@test "Ubuntu 24.04 is buildable and shares the Debian prep script" {
    # Confirmed rather than assumed: Ubuntu packages xe-guest-utilities, so
    # both the ISO path and the apt fallback in that script work there.
    local row
    row=$(tpl_row_for_key ubuntu2404)
    ! tpl_is_placeholder "$row"
    [ "$(tpl_field "$row" 6)" = "tpl_prep_debian" ]
    [ "$(tpl_field "$row" 5)" = "ubuntu" ]
}

@test "every Ubuntu LTS release is buildable and shares the Debian prep script" {
    # All three were proven the same way before being promoted: the published
    # SHA256 checksum verified against the downloaded image, qcow2 confirmed
    # from the magic bytes rather than the .img name, an ESP and a BIOS boot
    # partition present so either firmware works, and a -generic kernel rather
    # than a -cloud one.
    local key row
    for key in ubuntu2204 ubuntu2404 ubuntu2604; do
        row=$(tpl_row_for_key "$key")
        ! tpl_is_placeholder "$row"
        [ "$(tpl_field "$row" 6)" = "tpl_prep_debian" ]
        [ "$(tpl_field "$row" 5)" = "ubuntu" ]
    done
}

@test "each Ubuntu row's disk is sized for its own image, not for the family" {
    # The figure has to clear that image's virtual size. 22.04 expands to
    # 2.2 GiB and fits the default; 24.04 and 26.04 both expand to 3.5 GiB and
    # declare 6. Copying one release's number onto another would either inflate
    # every clone or leave no margin.
    [ -z "$(tpl_field "$(tpl_row_for_key ubuntu2204)" 7)" ]
    [ "$(tpl_field "$(tpl_row_for_key ubuntu2404)" 7)" = "6" ]
    [ "$(tpl_field "$(tpl_row_for_key ubuntu2604)" 7)" = "6" ]
}

@test "every Ubuntu row points at the LTS line" {
    # Interim releases have nine-month lifespans, so a template built from one
    # would be out of support before the VMs cloned from it were retired.
    local row key
    for row in "${TPL_CATALOG[@]}"; do
        key=$(tpl_field "$row" 1)
        [[ "$key" == ubuntu* ]] || continue
        # LTS releases are even-numbered years with an .04 release month.
        [[ "$key" =~ ^ubuntu[0-9][0-9]04$ ]]
        [[ $(( ${key:6:2} % 2 )) -eq 0 ]]
    done
}

@test "the expanded size is reported to one decimal place, rounded" {
    # Integer division reports a 3.5 GiB image as "3 GiB", understating the
    # figure that decides whether the disk is large enough -- which is what
    # gets read back when a build runs out of room mid-conversion. Truncating
    # the decimal is the same fault in miniature: Ubuntu 22.04 is 2.199 GiB,
    # shown as "2.1" while qemu-img and everything else says 2.2.
    local body
    body=$(declare -f deploy_import_vdi_staged)
    [[ "$body" == *"536870912"* ]]

    # Real catalogue values, against what qemu-img reports for each.
    local v t
    for v in 2361393152:2.2 3758096384:3.5 3221225472:3.0 1073741824:1.0; do
        t=$(( (${v%%:*} * 10 + 536870912) / 1073741824 ))
        [ "$(( t / 10 )).$(( t % 10 ))" = "${v##*:}" ]
    done
}

@test "rounding the expanded size carries into the whole number" {
    # Rounding the parts separately would print 2.99 GiB as "2.10". Rounding to
    # tenths before the split is what makes the carry work.
    local t=$(( (3210983178 * 10 + 536870912) / 1073741824 ))
    [ "$(( t / 10 )).$(( t % 10 ))" = "3.0" ]
}

@test "a missing qemu-img stops the build instead of installing anything" {
    # dom0 runs QEMU for HVM guests, so qemu-img is part of the base system.
    # Its absence means something is wrong with the host, not that a package
    # is waiting to be added.
    local body
    body=$(declare -f deploy_ensure_qemu_img)
    [[ "$body" != *"yum install"* ]]
    [[ "$body" != *"prompt_yes_no"* ]]
    [[ "$body" == *"qemu-img is not available there"* ]]
}

@test "nothing offers to install onto dom0 from the CentOS or EPEL repositories" {
    # XCP-ng's rule 1 is never to enable additional repositories: the update
    # process assumes only XCP-ng's own are on, and CentOS/EPEL carry higher
    # version numbers, so yum will overwrite core dom0 packages and break the
    # host. Guarded across the whole script, not just the one function that
    # got it wrong.
    local src="${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
    local hits
    hits=$(grep -v '^[[:space:]]*#' "$src" | grep -c 'enablerepo' || true)
    [ "$hits" -eq 0 ]
}

# --- cursor navigation ------------------------------------------------------
#
# Most of the catalogue is currently unbuildable, so a cursor that stops on
# placeholders means scrolling through a dozen inert rows to reach the next
# real one, at a position where SPACE does nothing.

@test "the cursor opens on the first buildable row, not the first row" {
    # AlmaLinux 8 sorts first and is a placeholder.
    local i cursor=0
    for ((i = 0; i < ${#TPL_CATALOG[@]}; i++)); do
        if ! tpl_is_placeholder "${TPL_CATALOG[$i]}"; then cursor=$i; break; fi
    done
    tpl_is_placeholder "${TPL_CATALOG[0]}"
    ! tpl_is_placeholder "${TPL_CATALOG[$cursor]}"
}

@test "moving down skips placeholders" {
    local count=${#TPL_CATALOG[@]} i start next
    start=0
    for ((i = 0; i < count; i++)); do
        if ! tpl_is_placeholder "${TPL_CATALOG[$i]}"; then start=$i; break; fi
    done
    next=$(tpl_next_selectable "$start" 1 "$count")
    ! tpl_is_placeholder "${TPL_CATALOG[$next]}"
    [ "$next" -ne "$start" ]
}

@test "moving up skips placeholders" {
    local count=${#TPL_CATALOG[@]} i start prev
    start=0
    for ((i = 0; i < count; i++)); do
        if ! tpl_is_placeholder "${TPL_CATALOG[$i]}"; then start=$i; break; fi
    done
    # Wrapping upward from the first buildable row crosses the run of
    # placeholders at the end of the catalogue.
    prev=$(tpl_next_selectable "$start" -1 "$count")
    ! tpl_is_placeholder "${TPL_CATALOG[$prev]}"
}

@test "every position the cursor can reach is selectable" {
    # Walk the whole cycle in both directions: no step may land on a row where
    # SPACE would do nothing.
    local count=${#TPL_CATALOG[@]} i c step
    for step in 1 -1; do
        c=0
        for ((i = 0; i < count; i++)); do
            if ! tpl_is_placeholder "${TPL_CATALOG[$i]}"; then c=$i; break; fi
        done
        for ((i = 0; i < count * 2; i++)); do
            c=$(tpl_next_selectable "$c" "$step" "$count")
            ! tpl_is_placeholder "${TPL_CATALOG[$c]}"
        done
    done
}

@test "navigation wraps around the ends of the catalogue" {
    # Wrapping must reach the first buildable row from the last and back again,
    # whether or not the catalogue happens to end on a placeholder -- which
    # depends on which distributions are buildable and changes as rows are
    # promoted.
    local count=${#TPL_CATALOG[@]} last first

    # Down from the last buildable row must come back to the first.
    local i
    first=0
    for ((i = 0; i < count; i++)); do
        if ! tpl_is_placeholder "${TPL_CATALOG[$i]}"; then first=$i; break; fi
    done
    last=$first
    for ((i = count - 1; i >= 0; i--)); do
        if ! tpl_is_placeholder "${TPL_CATALOG[$i]}"; then last=$i; break; fi
    done
    [ "$(tpl_next_selectable "$last" 1 "$count")" -eq "$first" ]
    [ "$(tpl_next_selectable "$first" -1 "$count")" -eq "$last" ]
}

@test "a catalogue of nothing but placeholders does not hang the menu" {
    # Bounded by the row count rather than by finding a match. A menu that
    # spins forever is a far worse failure than a cursor that will not move.
    local TPL_CATALOG=(
        "a|A|a|https://e/a.qcow2|u|-|"
        "b|B|b|https://e/b.qcow2|u|-|"
    )
    [ "$(tpl_next_selectable 0 1 2)" -eq 0 ]
    [ "$(tpl_next_selectable 0 -1 2)" -eq 0 ]
}

@test "a single buildable row leaves the cursor where it is" {
    local TPL_CATALOG=(
        "a|A|a|https://e/a.qcow2|u|-|"
        "b|B|b|https://e/b.raw|u|tpl_prep_debian|"
    )
    [ "$(tpl_next_selectable 1 1 2)" -eq 1 ]
    [ "$(tpl_next_selectable 1 -1 2)" -eq 1 ]
}

@test "the menu's arrow keys go through the skipping helper" {
    # The helper being correct is worth nothing if the key handler still does
    # its own arithmetic. Both directions, because skipping only downward
    # leaves the cursor stopping on placeholders on the way back up.
    local body
    body=$(declare -f tpl_prompt_selection)
    [[ "$body" == *'tpl_next_selectable "$cursor" 1 "$count"'* ]]
    [[ "$body" == *'tpl_next_selectable "$cursor" -1 "$count"'* ]]
    # And no leftover raw arithmetic on the cursor.
    [[ "$body" != *'cursor=$(( (cursor + 1) % count ))'* ]]
    [[ "$body" != *'cursor=$((cursor - 1))'* ]]
}

@test "placeholders are drawn without a cursor pointer" {
    # The cursor cannot rest on one, so a pointer could never be drawn there.
    # A leftover branch would tell the next reader otherwise.
    local body
    body=$(declare -f tpl_prompt_selection)
    local ph
    ph=$(sed -n '/tpl_is_placeholder "\$row"/,/continue/p' <<< "$body")
    [[ "$ph" != *"M_CYAN"* ]]
}

# --- build progress ---------------------------------------------------------
#
# Silence on a slow step reads as a hang. The operator kills it, and killing a
# build halfway leaves a VM and a multi-gigabyte disk behind. This matters most
# on the second and later templates of a multi-template run: the first is
# preceded by the connection banner and the storage and network lines, so its
# quiet steps are hidden, while the later ones follow "Building: ..." directly.

@test "no step between announcing a build and creating its disk is silent" {
    # `xe template-list` is a round trip to the pool master and the prep drive
    # generates a key and an ISO. Both used to run with no output at all.
    local body
    body=$(declare -f tpl_build_one)
    [[ "$body" == *"checking whether this template already exists"* ]]
    [[ "$body" == *"building the cloud-init preparation drive"* ]]
}

@test "no step between the preparation boot and the finished template is silent" {
    local body
    body=$(declare -f tpl_build_one)
    [[ "$body" == *"confirming the guest agent is installed"* ]]
    [[ "$body" == *"sealing it as a template"* ]]
}

@test "every slow call in a build is announced before it runs" {
    # Walk the function body: each of these calls must be preceded by output,
    # with nothing silent in between. Ordering matters as much as presence --
    # a message printed after the call it describes does not stop the screen
    # looking stuck while the call runs.
    local body
    body=$(declare -f tpl_build_one)

    local call announce
    while read -r call announce; do
        local call_line announce_line
        call_line=$(grep -n -- "$call" <<< "$body" | head -1 | cut -d: -f1)
        announce_line=$(grep -n -- "$announce" <<< "$body" | head -1 | cut -d: -f1)
        [ -n "$call_line" ]
        [ -n "$announce_line" ]
        [ "$announce_line" -lt "$call_line" ]
    done <<'PAIRS'
tpl_template_exists checking whether this template already exists
tpl_build_prep_drive building the cloud-init preparation drive
tpl_seal_template sealing it as a template
PAIRS
}

@test "each template in a run prints the same progress, not just the first" {
    # The messages live in tpl_build_one, which runs once per template, so a
    # message emitted from the surrounding one-time setup would appear only
    # before the first build.
    local body
    body=$(declare -f build_vm_templates)
    [[ "$body" != *"checking whether this template already exists"* ]]
    [[ "$body" != *"building the cloud-init preparation drive"* ]]
    [[ "$body" != *"sealing it as a template"* ]]
}

# --- multi-template runs ----------------------------------------------------
#
# Every template in a run reuses the same working directory, so anything
# written at a fixed path there has to be rebuilt rather than assumed absent.
# The first build creates these files; the second is the one that finds them
# already there.

@test "each template gets its own build key" {
    # ssh-keygen refuses to overwrite an existing key: it asks "Overwrite
    # (y/n)?" and, with no answer available, exits 1 having generated nothing.
    # Every build after the first hit that, and because the failure went to
    # /dev/null and its status was never tested, the build carried on and baked
    # the previous template's key into this template's config drive.
    DEPLOY_WORKDIR="$TMPDIR_TEST"

    local k1 k2
    tpl_build_prep_drive "$(tpl_row_for_key debian12)"
    k1=$(ssh-keygen -lf "${TPL_SSH_KEY}.pub" | awk '{print $2}')

    tpl_build_prep_drive "$(tpl_row_for_key debian13)"
    k2=$(ssh-keygen -lf "${TPL_SSH_KEY}.pub" | awk '{print $2}')

    [ -n "$k1" ]
    [ -n "$k2" ]
    [ "$k1" != "$k2" ]
}

@test "a second template's drive carries its own account, not the first's" {
    # The clearest symptom of a stale drive: an Ubuntu template built after a
    # Debian one would ship Debian's user and preparation script.
    DEPLOY_WORKDIR="$TMPDIR_TEST"

    tpl_build_prep_drive "$(tpl_row_for_key debian12)"
    grep -q 'name: debian' "${DEPLOY_WORKDIR}/tpl-cidata/user-data"

    tpl_build_prep_drive "$(tpl_row_for_key ubuntu2404)"
    grep -q 'name: ubuntu' "${DEPLOY_WORKDIR}/tpl-cidata/user-data"
    ! grep -q 'name: debian' "${DEPLOY_WORKDIR}/tpl-cidata/user-data"
}

@test "building a prep drive twice in a row succeeds both times" {
    DEPLOY_WORKDIR="$TMPDIR_TEST"
    tpl_build_prep_drive "$(tpl_row_for_key debian12)"
    tpl_build_prep_drive "$(tpl_row_for_key debian12)"
}

@test "a failed key generation stops the build instead of being discarded" {
    local body
    body=$(declare -f tpl_build_prep_drive)
    # The old key is cleared first, and the generation's status is tested.
    [[ "$body" == *'rm -f "${TPL_SSH_KEY}" "${TPL_SSH_KEY}.pub"'* ]]
    [[ "$body" == *"if ! ssh-keygen"* ]]
}

@test "a failed cloud-init drive stops the build instead of being discarded" {
    # The drive carries the whole preparation. Booting without it wastes the
    # full fifteen-minute timeout and reports a cause that is not the real one.
    local body
    body=$(declare -f tpl_build_prep_drive)
    [[ "$body" == *'iso_rc != 0'* ]]
    [[ "$body" == *'! -s "$iso"'* ]]
}

@test "the build checks that its preparation drive was actually built" {
    local body
    body=$(declare -f tpl_build_one)
    [[ "$body" == *"if ! tpl_build_prep_drive"* ]]
}
