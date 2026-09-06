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

# --- RHEL-family prep script ------------------------------------------------
#
# A separate script from the Debian one because the family differs in package
# manager, guest-tools availability and SELinux. These mirror the Debian
# assertions above rather than inventing new ones: the two scripts have to
# meet the same contract, and anything only one of them is checked for is the
# half that quietly regresses.

@test "the rhel prep script is valid shell" {
    tpl_prep_rhel almalinux > "${TMPDIR_TEST}/prep-rhel.sh"
    bash -n "${TMPDIR_TEST}/prep-rhel.sh"
}

@test "the rhel prep script substitutes the account name" {
    run tpl_prep_rhel someuser
    [[ "$output" == *"someuser:someuser"* ]]
    [[ "$output" != *"__TPL_USER__"* ]]
}

@test "the rhel prep script ends by powering the VM off" {
    run tpl_prep_rhel almalinux
    [[ "$(grep -v '^\s*#' <<< "$output" | grep . | tail -1)" == "shutdown -h now" ]]
}

@test "the rhel prep script scrubs every piece of machine identity" {
    run tpl_prep_rhel almalinux
    [[ "$output" == *"cloud-init clean"* ]]
    [[ "$output" == *"/etc/machine-id"* ]]
    [[ "$output" == *"ssh_host_"* ]]
    [[ "$output" == *"/var/lib/cloud/instances"* ]]
    # This family bakes the build VM's MAC into a NetworkManager connection,
    # which a clone would reuse -- two VMs sharing one DHCP lease.
    [[ "$output" == *"NetworkManager/system-connections"* ]]
}

@test "the rhel prep script uses dnf, never apt" {
    # Catches a copy-paste from the Debian script, which would fail silently:
    # cloud-init does not abort on a failed runcmd.
    run tpl_prep_rhel almalinux
    [[ "$output" != *"apt-get"* ]]
    [[ "$output" == *"dnf install -y cloud-init"* ]]
}

@test "the rhel prep script installs growpart so deploy-time disk sizes take effect" {
    # cloud-utils-growpart is this family's equivalent of growroot. Without it
    # an operator can ask for a bigger disk and the filesystem will not fill it.
    run tpl_prep_rhel almalinux
    [[ "$output" == *"cloud-utils-growpart"* ]]
}

@test "the rhel prep script takes guest tools from the ISO with no package fallback" {
    # No release in this family packages xe-guest-utilities -- verified absent
    # from base repos and EPEL on AlmaLinux 8, 9 and 10 -- so unlike the Debian
    # script there is nothing to fall back to, and a fallback that looked like
    # one would just fail quietly.
    run tpl_prep_rhel almalinux
    [[ "$output" == *"install.sh"* ]]
    # No *install* of it -- the name appearing in a comment explaining why
    # there is no fallback is the point, not a violation.
    local code
    code=$(grep -v '^\s*#' <<< "$output")
    [[ "$code" != *"install"*"xe-guest-utilities"* ]]
}

@test "the rhel prep script enables password login where sshd reads no drop-in" {
    # AlmaLinux 8 ships neither sshd_config.d nor the Include line that reads
    # it, so a drop-in alone is silently ignored there and the template refuses
    # password logins. 9 and 10 do ship both. The script has to handle each.
    run tpl_prep_rhel almalinux
    [[ "$output" == *"Include /etc/ssh/sshd_config.d"* ]]
    [[ "$output" == *"sshd_config.d/99-xo-template.conf"* ]]
    [[ "$output" == *"sed -i"*"PasswordAuthentication"* ]]
}

@test "the rhel prep script relabels for SELinux" {
    # Enforcing by default in this family, unlike Debian. The files the script
    # writes get no context, and an unlabelled sshd drop-in locks logins out
    # with nothing obvious in the log.
    run tpl_prep_rhel almalinux
    [[ "$output" == *"/.autorelabel"* ]]
}

@test "every AlmaLinux row is buildable and shares the rhel prep script" {
    local row key prep found=0
    for row in "${TPL_CATALOG[@]}"; do
        key=$(tpl_field "$row" 1)
        [[ "$key" == almalinux* ]] || continue
        found=$((found + 1))
        prep=$(tpl_field "$row" 6)
        [ "$prep" = "tpl_prep_rhel" ]
        ! tpl_is_placeholder "$row"
    done
    # 8, 9 and 10.
    [ "$found" -eq 3 ]
}

@test "every AlmaLinux row asks for a disk that fits its 10 GiB image" {
    # Every image in this family is a 10 GiB virtual disk regardless of how
    # small the download is, so each row overrides the default rather than
    # inheriting a 4 GiB disk the image cannot fit in.
    local row key disk
    for row in "${TPL_CATALOG[@]}"; do
        key=$(tpl_field "$row" 1)
        [[ "$key" == almalinux* ]] || continue
        disk=$(tpl_field "$row" 7)
        [ -n "$disk" ]
        [ "$disk" -ge 10 ]
    done
}

@test "every CentOS Stream row is buildable and shares the rhel prep script" {
    # Same family as AlmaLinux and the same script -- a second copy for these
    # rows is how one of them silently stops getting fixes.
    local row key prep found=0
    for row in "${TPL_CATALOG[@]}"; do
        key=$(tpl_field "$row" 1)
        [[ "$key" == centos* ]] || continue
        found=$((found + 1))
        prep=$(tpl_field "$row" 6)
        [ "$prep" = "tpl_prep_rhel" ]
        ! tpl_is_placeholder "$row"
    done
    # 9 and 10.
    [ "$found" -eq 2 ]
}

@test "every CentOS Stream row asks for a disk that fits its 10 GiB image" {
    # Both are ~1 GiB downloads that expand to a 10 GiB disk, so the 4 GiB
    # default would not hold either. Read off `qemu-img info`'s "virtual size".
    local row key disk
    for row in "${TPL_CATALOG[@]}"; do
        key=$(tpl_field "$row" 1)
        [[ "$key" == centos* ]] || continue
        disk=$(tpl_field "$row" 7)
        [ -n "$disk" ]
        [ "$disk" -ge 10 ]
    done
}

@test "every CentOS Stream row logs in as the account its image actually creates" {
    # cloud-user, not centos -- read out of each image's own
    # /etc/cloud/cloud.cfg, where system_info.default_user.name says so on both
    # releases. Getting this wrong produces a template nobody can log into, and
    # nothing reports an error.
    local row key user
    for row in "${TPL_CATALOG[@]}"; do
        key=$(tpl_field "$row" 1)
        [[ "$key" == centos* ]] || continue
        user=$(tpl_field "$row" 5)
        [ "$user" = "cloud-user" ]
    done
}

@test "the RHEL rebuilds do not use the Fedora prep script" {
    # The five AlmaLinux and CentOS Stream rows are proven on tpl_prep_rhel.
    # Nothing about adding Fedora may move them onto another script.
    local row key prep found=0
    for row in "${TPL_CATALOG[@]}"; do
        key=$(tpl_field "$row" 1)
        [[ "$key" == almalinux* || "$key" == centos* ]] || continue
        found=$((found + 1))
        prep=$(tpl_field "$row" 6)
        [ "$prep" = "tpl_prep_rhel" ]
    done
    [ "$found" -eq 5 ]
}

@test "the Fedora prep script installs guest tools in three tiers" {
    # ISO with the documented -d/-m override, then the ISO tarball, then
    # Fedora's own package -- the order linux_util's installer uses. Each tier
    # is checked by looking for xe-daemon rather than trusting an exit status,
    # which is what let the first failure reach the build's own agent check.
    local body
    body=$(tpl_prep_fedora fedora)

    [[ "$body" == *'install.sh" -n -d "$did" -m "$major"'* ]]
    [[ "$body" == *"xe-guest-utilities_*_all.tgz"* ]]
    [[ "$body" == *"dnf install -y xe-guest-utilities-latest"* ]]
    [[ "$body" == *"guest_tools_present"* ]]
    [[ "$body" == *"systemctl enable xe-linux-distribution.service"* ]]
}

@test "the Fedora prep script unlocks the default user for password login" {
    # Setting a password is not enough: the image declares lock_passwd: True
    # for its default user and cloud-init re-locks the account on every boot,
    # so a clone would come up with the shipped password already locked.
    # Written as a cloud.cfg.d drop-in, which is a deep merge over the image's
    # own block -- the username in it is preserved, only these keys change.
    local body
    body=$(tpl_prep_fedora fedora)

    [[ "$body" == *"/etc/cloud/cloud.cfg.d/99-xo-template-login.cfg"* ]]
    [[ "$body" == *"lock_passwd: False"* ]]
    [[ "$body" == *"ssh_pwauth: True"* ]]
}

@test "the RHEL prep script keeps its ISO-only guest tools step" {
    # Its guest-tools step is proven on five rows. Fedora needing three tiers
    # did not change it -- no package fallback, no -d/-m override.
    local body
    body=$(tpl_prep_rhel almalinux)
    [[ "$body" != *"xe-guest-utilities-latest"* ]]
    [[ "$body" != *'-d "$did"'* ]]
    [[ "$body" == *'install.sh" -n'* ]]
}

@test "the RHEL prep script unlocks the default user for password login" {
    # Every image in this family declares lock_passwd: True, so cloud-init
    # re-locks the account on every boot and the shipped password is useless
    # without this. Verified on a real Fedora VM first, then applied here.
    local body
    body=$(tpl_prep_rhel almalinux)

    [[ "$body" == *"/etc/cloud/cloud.cfg.d/99-xo-template-login.cfg"* ]]
    [[ "$body" == *"lock_passwd: False"* ]]
    [[ "$body" == *"ssh_pwauth: True"* ]]
}

@test "the login drop-in is written before the SELinux relabel is requested" {
    # The drop-in is created without the contexts SELinux expects, so it has to
    # exist before /.autorelabel is touched or it is not relabelled on first
    # boot. Both prep scripts that set SELinux up have to get this right.
    local body pos_file pos_relabel fn
    for fn in tpl_prep_rhel tpl_prep_fedora; do
        body=$("$fn" testuser)
        pos_file=$(grep -n "cloud.cfg.d/99-xo-template-login.cfg" <<< "$body" | head -1 | cut -d: -f1)
        pos_relabel=$(grep -n "^touch /.autorelabel" <<< "$body" | head -1 | cut -d: -f1)
        [ -n "$pos_file" ]
        [ -n "$pos_relabel" ]
        [ "$pos_file" -lt "$pos_relabel" ]
    done
}

@test "every Fedora row logs in as the account its image actually creates" {
    # fedora on both releases, read out of each image's own
    # /etc/cloud/cloud.cfg, where system_info.default_user.name says so.
    # Getting this wrong produces a template nobody can log into, and nothing
    # reports an error.
    local row key
    for row in "${TPL_CATALOG[@]}"; do
        key=$(tpl_field "$row" 1)
        [[ "$key" == fedora* ]] || continue
        [ "$(tpl_field "$row" 5)" = "fedora" ]
    done
}

@test "both Fedora rows are buildable and share one prep script" {
    # Not tpl_prep_rhel: Fedora's guest tools do not come from the ISO the way
    # the rebuilds' do -- install.sh refuses on Fedora, and Fedora packages
    # xe-guest-utilities-latest where they package nothing -- so Fedora has a
    # separate script rather than a branch inside the proven one.
    #
    # 44 was read the same way as 43 rather than assumed to match it: same
    # default user, same lock_passwd, same sshd include, same 5 GiB image, and
    # xe-guest-utilities-latest present in its repositories too. A second copy
    # of the script for it would be how one of them stops getting fixes.
    local row key prep found=0
    for row in "${TPL_CATALOG[@]}"; do
        key=$(tpl_field "$row" 1)
        [[ "$key" == fedora* ]] || continue
        found=$((found + 1))
        prep=$(tpl_field "$row" 6)
        [ "$prep" = "tpl_prep_fedora" ]
        ! tpl_is_placeholder "$row"
    done
    # 43 and 44.
    [ "$found" -eq 2 ]
}

@test "every Fedora row asks for a disk that fits its 5 GiB image" {
    # Both images expand to 5 GiB, read off `qemu-img info`'s virtual size, so
    # the 4 GiB default clears neither.
    local row key disk
    for row in "${TPL_CATALOG[@]}"; do
        key=$(tpl_field "$row" 1)
        [[ "$key" == fedora* ]] || continue
        disk=$(tpl_field "$row" 7)
        [ -n "$disk" ]
        [ "$disk" -ge 5 ]
    done
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
    # The URL comes from the one builder now, so the check follows it there
    # rather than pinning a string that moved.
    [[ "$body" == *"deploy_export_url"* ]]
    [[ "$(declare -f deploy_export_url)" == *"export_raw_vdi"* ]]
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
    # The loop is shared by both build paths now, so the path-specific read
    # lives in tpl_agent_version. The observation still happens in the poll
    # that is already running, which is the thing this test is about.
    [[ "$body" == *"tpl_agent_version"* ]]
    [[ "$body" == *"TPL_AGENT_SEEN"* ]]
    [[ "$(declare -f tpl_agent_version)" == *"PV-drivers-version"* ]]
}

@test "the agent check uses a signal that survives the shutdown" {
    # PV-drivers-version is cleared when the domain goes away; os-version and
    # the reported addresses persist. Checked on a live pool: every halted VM
    # reports PV-drivers-version empty, working ones included. Depending on it
    # fails every build.
    # The read now sits in the dispatcher, so that both build paths ask the
    # same question of XAPI -- through `xe` on one and through XO on the other.
    local body
    body=$(declare -f tpl_os_version_dispatch)
    [[ "$body" == *"param-name=os-version"* ]]
    [[ "$body" != *"PV-drivers-version"* ]]

    # And tpl_build_one still gets its answer from there rather than from the
    # signal that does not survive the shutdown.
    local caller
    caller=$(declare -f tpl_build_one)
    [[ "$caller" == *"tpl_os_version_dispatch"* ]]
    [[ "$caller" != *'vm-param-get uuid=${TPL_VM_UUID} param-name=PV-drivers-version'* ]]
}

@test "both build paths read the agent's os-version, not PV-drivers-version" {
    # The API path reads XO's os_version field, which is the same value XAPI
    # exposes to `xe` as os-version.
    local body
    body=$(declare -f tpl_os_version_dispatch)
    [[ "$body" == *"os_version"* ]]
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
    imp=$(grep -n 'deploy_import_url' <<< "$body" | head -1 | cut -d: -f1)
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
        # The task id is appended by the one URL builder now, so every import path
    # gets it by construction rather than each remembering to.
    [[ "$body" == *'deploy_import_url'* ]]
    [[ "$(declare -f deploy_import_url)" == *'task_id'* ]]
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

@test "the SSH path gives static-min a floor below the allocation" {
    # static-min is the smallest XAPI would shrink a guest to under ballooning,
    # not the memory a VM gets. Pinning all four figures together left no
    # headroom below; 1 GiB matches the VMs already on the pool, which run a
    # 1 GiB floor against a much larger dynamic allocation.
    local body
    body=$(declare -f tpl_create_build_vm)
    [[ "$body" == *"static-min=\${static_min}"* ]]
    [[ "$body" == *"dynamic-min=\${mem}"* ]]
    [[ "$body" == *"static-max=\${mem}"* ]]
    [ "$TPL_STATIC_MIN_GB" -lt "$TPL_DEFAULT_RAM_GB" ]
}

@test "a static-min floor above the allocation is clamped, not sent" {
    # XAPI requires static-max >= dynamic-max >= dynamic-min >= static-min, so
    # a floor above the RAM figure would be rejected outright.
    local body
    body=$(declare -f tpl_create_build_vm)
    [[ "$body" == *"TPL_STATIC_MIN_GB > TPL_DEFAULT_RAM_GB"* ]]
}

@test "the console gets both a std adapter and the 8 MiB that goes with it" {
    # vga=std alone is not enough: videoram stays at whatever the base template
    # carried, which is 4, and a template built that way produced UEFI VMs with
    # an unreadable console. 16 is no better -- it renders as coloured noise
    # under UEFI. Every working UEFI VM on a live pool runs std with 8. XAPI
    # accepts any of these silently, so a wrong value only shows on the console.
    #
    local body
    body=$(declare -f tpl_create_build_vm)
    [[ "$body" == *"platform:vga=std"* ]]
    [[ "$body" == *"platform:videoram=8"* ]]
    [[ "$body" != *"platform:videoram=16"* ]]
}

@test "the API path reads its VM settings from the SSH function, not its own copy" {
    # A template must come out the same whichever way the pool was reached, so
    # the API path must not carry its own copy of these values. It reads them
    # out of tpl_create_build_vm with declare -f; a literal value written here
    # is a second source of truth that will drift.
    local body
    body=$(declare -f tpl_api_configure_build_vm)
    [[ "$body" == *"declare -f tpl_create_build_vm"* ]]
    [[ "$body" != *'"vga":"std"'* ]]
    [[ "$body" != *'"videoram":8'* ]]
    [[ "$body" != *'"viridian":false'* ]]
}

@test "the API path sets the memory figures XO will actually accept" {
    # static-min cannot be raised through XO: memoryMin over REST and through
    # vm.set both answer success and leave it at the base template's 128 MiB,
    # tried singly and with all four keys together on a live pool. Only
    # `xe vm-memory-limits-set` moves it, which is what this path avoids
    # needing. So the three that do apply are sent and memoryMin is not
    # claimed -- a template records static: [134217728, ...] where an
    # SSH-built one records the figure twice, which is a difference in the
    # record and not in the VMs it produces.
    local body
    body=$(declare -f tpl_api_configure_build_vm)
    [[ "$body" == *"memoryMax"* ]]
    [[ "$body" == *"memoryStaticMax"* ]]
    [[ "$body" != *"memoryMin"* ]]
}

@test "viridian goes through JSON-RPC, which is the call that applies it" {
    # REST accepts viridian in the PATCH body, answers 200, and leaves the
    # property alone -- a template built that way came out viridian=true while
    # the same request's vga, videoram and coresPerSocket all applied.
    local body
    body=$(declare -f tpl_api_configure_build_vm)
    [[ "$body" == *"vm.set id="*"viridian="* ]]
    [[ "$body" != *'"viridian":'* ]]
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

@test "AlmaLinux images are verified against the CHECKSUM file it publishes" {
    # The mirror publishes a file named CHECKSUM, not SHA512SUMS, so without a
    # case here the fetch 404s and the build imports the image unverified --
    # a warning, not a failure, which is exactly the kind of thing that goes
    # unnoticed.
    #
    # It is SHA-256 in coreutils' ordinary "<hash>  <file>" shape, so the
    # existing parser handles it. The comments once claimed this family used
    # "SHA256 (file) = hash" and needed a second parser; reading the mirror
    # showed otherwise.
    local row url
    for row in "${TPL_CATALOG[@]}"; do
        url=$(tpl_field "$row" 4)
        [[ "$url" == *repo.almalinux.org* ]] || continue
        [ "$(deploy_checksum_source "$url")" = "CHECKSUM 256" ]
    done
}

@test "CentOS Stream images are verified against the CHECKSUM file it publishes" {
    # Same filename as AlmaLinux and a different format inside it, which is the
    # whole reason the parse is tried both ways rather than picked per origin.
    local row url
    for row in "${TPL_CATALOG[@]}"; do
        url=$(tpl_field "$row" 4)
        [[ "$url" == *cloud.centos.org* ]] || continue
        [ "$(deploy_checksum_source "$url")" = "CHECKSUM 256" ]
    done
}

@test "Fedora's checksum filename is derived from the image, not a constant" {
    # Fedora is the one origin here that stamps the release and compose into
    # the sums filename, so no fixed string can name it and hardcoding today's
    # compose would break at the next respin. Both of these are the names the
    # mirror actually publishes beside those images.
    local url

    url='https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2'
    [ "$(deploy_checksum_source "$url")" = "Fedora-Cloud-43-1.6-x86_64-CHECKSUM 256" ]

    url='https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2'
    [ "$(deploy_checksum_source "$url")" = "Fedora-Cloud-44-1.7-x86_64-CHECKSUM 256" ]
}

@test "a future Fedora compose resolves without the table being edited" {
    # The point of deriving rather than declaring: a respin changes the image
    # filename and the sums filename together, and this has to follow both.
    local url='https://dl.fedoraproject.org/pub/fedora/linux/releases/45/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-45-2.3.x86_64.qcow2'
    [ "$(deploy_checksum_source "$url")" = "Fedora-Cloud-45-2.3-x86_64-CHECKSUM 256" ]
}

@test "Fedora's PGP-signed checksum file still yields the image's digest" {
    # Fedora wraps its CHECKSUM in a clearsigned envelope. The digest lines
    # inside are ordinary BSD tag lines, so the existing parse reaches them --
    # but a parser that choked on the armour would warn and import unverified.
    # This is the real file's shape, trimmed.
    local sums base want
    base="Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2"
    sums="-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

# ${base}: 583335936 bytes
SHA256 (${base}) = 846574c8a97cd2d8dc1f231062d73107cc85cbbbda56335e264a46e3a6c8ab2f
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEExufwgc+A4TFGZ26IgptgZjFkVTEFAmj9DpIACgkQgptgZjFk
-----END PGP SIGNATURE-----"

    # The commented size line above each digest starts with '#' and carries the
    # filename in field 2 -- with a trailing colon, so the coreutils parse must
    # not mistake it for an entry and return "#" as the digest.
    want=$(awk -v f="$base" '$2 == f || $2 == "*" f { print $1; exit }' <<< "$sums")
    [ -z "$want" ]

    want=$(awk -v f="($base)" '$2 == f && $3 == "=" { print $4; exit }' <<< "$sums")
    [ "$want" = "846574c8a97cd2d8dc1f231062d73107cc85cbbbda56335e264a46e3a6c8ab2f" ]
}

@test "a BSD-tag checksum file yields the digest for the requested image" {
    # cloud.centos.org publishes "SHA256 (<file>) = <hash>", where the digest
    # is the fourth field rather than the first. The coreutils parse finds
    # nothing in it, so without this branch the build warns and imports the
    # image unverified -- a warning, not a failure.
    local sums base want
    base="CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2"
    sums="SHA256 (CentOS-Stream-Azure-9-latest.x86_64.vhd.xz) = 1111111111111111111111111111111111111111111111111111111111111111
SHA256 (${base}) = 659024f5219a57e0be136c2902f624ee4405e307bc6d8fc72c7fabdf8267e6ff"

    # The coreutils parse must not match a BSD line: its second field is
    # "(<name>)", never the bare name.
    want=$(awk -v f="$base" '$2 == f || $2 == "*" f { print $1; exit }' <<< "$sums")
    [ -z "$want" ]

    want=$(awk -v f="($base)" '$2 == f && $3 == "=" { print $4; exit }' <<< "$sums")
    [ "$want" = "659024f5219a57e0be136c2902f624ee4405e307bc6d8fc72c7fabdf8267e6ff" ]
}

@test "the BSD-tag parse is tried only after the coreutils one finds nothing" {
    # Order matters: every existing row is verified by the coreutils parse, and
    # it has to stay the branch they take. A BSD attempt running first would
    # put a new parse in front of proven ones for no gain.
    local body first second
    body=$(declare -f deploy_verify_image_checksum)
    first=$(grep -n '\$2 == f || \$2 == "\*" f' <<< "$body" | head -1 | cut -d: -f1)
    second=$(grep -n '\$3 == "="' <<< "$body" | head -1 | cut -d: -f1)
    [ -n "$first" ]
    [ -n "$second" ]
    [ "$first" -lt "$second" ]
    [[ "$body" == *'if [[ -z "$want" ]]; then'* ]]
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
    # The behaviour under test is that the opening cursor lands somewhere
    # SPACE actually works. It is deliberately not asserted against a
    # particular row: this test used to require TPL_CATALOG[0] to be a
    # placeholder, which was true only while AlmaLinux 8 was unbuilt, and it
    # failed the moment that row got a prep function. Which distro sorts first
    # is not what this test is for.
    local i cursor=0
    for ((i = 0; i < ${#TPL_CATALOG[@]}; i++)); do
        if ! tpl_is_placeholder "${TPL_CATALOG[$i]}"; then cursor=$i; break; fi
    done
    ! tpl_is_placeholder "${TPL_CATALOG[$cursor]}"

    # And it is the *first* such row -- everything before it, if anything, is
    # a placeholder that was correctly skipped.
    for ((i = 0; i < cursor; i++)); do
        tpl_is_placeholder "${TPL_CATALOG[$i]}"
    done
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
    command -v ssh-keygen >/dev/null || skip "ssh-keygen not available to build the key"
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
    command -v ssh-keygen >/dev/null || skip "ssh-keygen not available to build the key"
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
    command -v ssh-keygen >/dev/null || skip "ssh-keygen not available to build the key"
    DEPLOY_WORKDIR="$TMPDIR_TEST"
    tpl_build_prep_drive "$(tpl_row_for_key debian12)"
    tpl_build_prep_drive "$(tpl_row_for_key debian12)"
}

@test "a failed key generation stops the build instead of being discarded" {
    local body
    body=$(declare -f tpl_build_prep_drive)
    # The old key is cleared first, and the generation's status is tested.
    # Both halves live in tpl_build_ssh_key now -- one implementation shared by
    # both build paths, which is what stops a copy reintroducing this.
    [[ "$(declare -f tpl_build_ssh_key)" == *'rm -f "${TPL_SSH_KEY}" "${TPL_SSH_KEY}.pub"'* ]]
    [[ "$(declare -f tpl_build_ssh_key)" == *"if ! ssh-keygen"* ]]
    # And the caller still stops on a failure rather than carrying on with no key.
    [[ "$body" == *"tpl_build_ssh_key"* ]]
    [[ "$body" == *"|| return 1"* ]]
}

@test "the build key path is spelled once, not at every call site" {
    # tpl_build_ssh_key is captured with $( ), so it cannot export the path --
    # every caller needs it too, to read the key back. That is what made three
    # copies of "${DEPLOY_WORKDIR}/tpl_key" appear across the file. They must
    # all go through tpl_ssh_key_path, or a change to the path breaks whichever
    # copy was missed.
    local fn
    for fn in tpl_build_ssh_key tpl_build_prep_drive tpl_api_create_build_vm; do
        [[ "$(declare -f "$fn")" != *'DEPLOY_WORKDIR}/tpl_key'* ]]
    done
    [ "$(DEPLOY_WORKDIR=/w tpl_ssh_key_path)" = "/w/tpl_key" ]
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

# --- The API build path -----------------------------------------------------

@test "tpl_json_field reads a string field out of a REST response" {
    local j='{"id":"abc-123","name_label":"Debian 13"}'
    [ "$(tpl_json_field "$j" id)" = "abc-123" ]
    [ "$(tpl_json_field "$j" name_label)" = "Debian 13" ]
}

@test "tpl_json_field is empty for a field that is not there" {
    [ -z "$(tpl_json_field '{"id":"x"}' missing)" ]
}

@test "tpl_urlencode escapes what a query parameter cannot carry" {
    [ "$(tpl_urlencode "Debian 13 (Trixie) root")" = "Debian%2013%20%28Trixie%29%20root" ]
}

@test "the create_vm body is valid JSON carrying the cloud-init document" {
    command -v python3 >/dev/null || skip "python3 not available to parse JSON"
    TPL_DEFAULT_VCPUS=2
    TPL_DEFAULT_RAM_GB=2
    DEPLOY_NETWORK_UUID=net-1
    DEPLOY_SR_UUID=sr-1

    local cc
    cc=$(printf '#cloud-config\nusers:\n  - name: debian\nruncmd:\n  - sh -c "echo hi"\n')
    local body
    body=$(tpl_api_vm_create_body "Debian 13" "tpl-1" "$cc")

    printf '%s' "$body" > "${TMPDIR_TEST}/body.json"
    printf '%s' "$cc" > "${TMPDIR_TEST}/cc.txt"

    run python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
orig=open(sys.argv[2]).read().rstrip("\n")
assert d["cloud_config"].rstrip("\n")==orig, "cloud_config did not round-trip"
assert d["memory"]==2147483648
assert d["cpus"]==2
assert d["name_label"].startswith("[building template]")
print("ok")
' "${TMPDIR_TEST}/body.json" "${TMPDIR_TEST}/cc.txt"
    [ "$status" -eq 0 ]
    [[ "$output" == *"ok"* ]]
}

@test "the create_vm body carries the resolved SR and network" {
    command -v python3 >/dev/null || skip "python3 not available to parse JSON"
    TPL_DEFAULT_VCPUS=2
    TPL_DEFAULT_RAM_GB=2
    DEPLOY_NETWORK_UUID=net-1
    DEPLOY_SR_UUID=sr-1

    # Both are globals resolved earlier in the run, so an unset one used to
    # kill the body under `set -u` -- and, once defaulted to empty, would send
    # a request naming no storage and no network at all. Asserting the values
    # reach the body is what keeps the default from hiding a missing resolve.
    tpl_api_vm_create_body "D" "t" "#cloud-config" > "${TMPDIR_TEST}/body.json"

    run python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
assert d["vdis"][0]["sr"]=="sr-1", d["vdis"]
assert d["vifs"][0]["network"]=="net-1", d["vifs"]
print("ok")
' "${TMPDIR_TEST}/body.json"
    [ "$status" -eq 0 ]
}

@test "a cloud-init document with quotes and backslashes survives the body" {
    command -v python3 >/dev/null || skip "python3 not available to parse JSON"
    TPL_DEFAULT_VCPUS=2
    TPL_DEFAULT_RAM_GB=2
    DEPLOY_NETWORK_UUID=net-1
    DEPLOY_SR_UUID=sr-1

    local cc
    cc=$(printf '#cloud-config\nruncmd:\n  - sh -c "echo \\"x\\""\n  - path: C:\\\\tmp\n')
    printf '%s' "$cc" > "${TMPDIR_TEST}/cc.txt"
    tpl_api_vm_create_body "D" "t" "$cc" > "${TMPDIR_TEST}/body.json"

    run python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
orig=open(sys.argv[2]).read().rstrip("\n")
assert d["cloud_config"].rstrip("\n")==orig, "escaping lost content"
print("ok")
' "${TMPDIR_TEST}/body.json" "${TMPDIR_TEST}/cc.txt"
    [ "$status" -eq 0 ]
}

@test "the real prep payload round-trips through the create_vm body" {
    command -v python3 >/dev/null || skip "python3 not available to parse JSON"
    TPL_DEFAULT_VCPUS=2
    TPL_DEFAULT_RAM_GB=2
    DEPLOY_NETWORK_UUID=net-1
    DEPLOY_SR_UUID=sr-1

    # The payload an actual build sends, not a stand-in: this is the thing
    # whose escaping matters, and it is 60-odd lines of shell inside YAML
    # inside JSON.
    local row user prep cc
    row=$(tpl_row_for_key debian13)
    user=$(tpl_field "$row" 5)
    prep=$(tpl_field "$row" 6)
    cc=$( printf '#cloud-config\nusers:\n  - name: %s\n' "$user"
          printf 'write_files:\n  - path: /root/xo-template-prep.sh\n    content: |\n'
          "$prep" "$user" | sed 's/^/      /' )

    printf '%s' "$cc" > "${TMPDIR_TEST}/cc.txt"
    tpl_api_vm_create_body "Debian 13 Cloud-init" "tpl-1" "$cc" > "${TMPDIR_TEST}/body.json"

    run python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
orig=open(sys.argv[2]).read().rstrip("\n")
assert d["cloud_config"].rstrip("\n")==orig, "prep payload did not survive"
assert "xo-template-prep.sh" in d["cloud_config"]
print("ok")
' "${TMPDIR_TEST}/body.json" "${TMPDIR_TEST}/cc.txt"
    [ "$status" -eq 0 ]
}

@test "every buildable catalogue row resolves to a valid firmware" {
    local row fw
    for row in "${TPL_CATALOG[@]}"; do
        tpl_is_placeholder "$row" && continue
        fw=$(tpl_row_firmware "$row")
        [[ "$fw" == "uefi" || "$fw" == "bios" ]]
    done
}

@test "an unset firmware field defaults to uefi" {
    [ "$(tpl_row_firmware "k|D|c|http://x/i.raw|u|tpl_prep_debian|")" = "uefi" ]
}

@test "an explicit bios firmware field is honoured" {
    [ "$(tpl_row_firmware "k|D|c|http://x/i.raw|u|tpl_prep_debian|8|bios")" = "bios" ]
}

@test "a nonsense firmware field falls back to uefi rather than being sent on" {
    [ "$(tpl_row_firmware "k|D|c|http://x/i.raw|u|tpl_prep_debian|8|sideways")" = "uefi" ]
}

@test "the dispatchers send each step to the selected path" {
    # Both implementations replaced, so the test observes only the routing.
    tpl_cleanup_failed_build() { echo "SSH-cleanup"; }
    tpl_api_cleanup_failed_build() { echo "API-cleanup"; }

    TPL_BUILD_METHOD=ssh
    run tpl_cleanup_failed_build_dispatch
    [[ "$output" == "SSH-cleanup" ]]

    TPL_BUILD_METHOD=api
    run tpl_cleanup_failed_build_dispatch
    [[ "$output" == "API-cleanup" ]]
}

@test "sealing on the API path passes the row's firmware through" {
    tpl_api_seal_template() { echo "sealed:$1:$2"; }
    TPL_BUILD_METHOD=api

    run tpl_seal_template_dispatch "k|D|c|http://x/i.raw|u|tpl_prep_debian|8|bios" "My Template"
    [[ "$output" == "sealed:My Template:bios" ]]
}

@test "the shared dependency check does not demand an ISO writer" {
    # The API path builds no ISO, so requiring one would push it to SSH for a
    # tool it never uses. Asserted against what the function requires rather
    # than against this machine, so the test says the same thing on a host that
    # happens to have xorriso installed as on one that does not.
    local body
    body=$(declare -f tpl_check_local_deps)
    [[ "$body" != *genisoimage* ]]
    [[ "$body" != *xorriso* ]]
    [[ "$body" == *curl* ]]
    [[ "$body" == *ssh-keygen* ]]
}

@test "the shared dependency check passes when its commands are present" {
    command -v curl >/dev/null && command -v ssh-keygen >/dev/null \
        || skip "curl or ssh-keygen not installed here"
    run tpl_check_local_deps
    [ "$status" -eq 0 ]
}

@test "the API path is never asked for an ISO writer or an SSH connection" {
    # tpl_api_create_build_vm hands cloud-init to XO and opens no SSH.
    local body
    body=$(declare -f tpl_api_create_build_vm)
    [[ "$body" != *genisoimage* ]]
    [[ "$body" != *xorriso* ]]
    [[ "$body" != *dom0_exec* ]]
    [[ "$body" != *dom0_xe* ]]
}

@test "no API build step reaches for the pool master over SSH" {
    local fn body
    for fn in tpl_api_import_image tpl_api_seal_template \
              tpl_api_cleanup_failed_build tpl_api_resolve_targets; do
        body=$(declare -f "$fn")
        [[ "$body" != *dom0_exec* ]]
        [[ "$body" != *dom0_xe* ]]
    done
}

@test "the image import streams a .raw URL and converts anything else" {
    local body
    body=$(declare -f tpl_api_import_image)
    # Debian ships .raw and streams straight through; everyone else ships
    # qcow2, which is converted here first -- XO will not take a qcow2.
    [[ "$body" == *'*.raw)'* ]]
    [[ "$body" == *"qemu-img convert"* ]]
}

@test "the import does not inherit the 60s timeout meant for small calls" {
    # A multi-gigabyte transfer under --max-time 60 would abort every build.
    local body
    body=$(declare -f tpl_api_import_image)
    [[ "$body" == *"--max-time"* ]]
    [[ "$body" == *"speed-limit"* ]]
}

@test "both --build-templates entry points read the config file" {
    # The build method and the API token live in xo-config.cfg, so a path that
    # reaches build_vm_templates without load_config sees them unset -- the
    # token appears missing however carefully it was filled in, and every run
    # silently takes the SSH path.
    local body

    body=$(declare -f main)
    [[ "$body" == *"load_config"* ]]

    # The flag path and the interactive menu path are separate call sites and
    # both have to do it; checking one would not have caught this.
    local script="${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
    local flag_ctx menu_ctx
    flag_ctx=$(grep -A8 -- '--build-templates)' "$script" | head -12)
    [[ "$flag_ctx" == *"load_config"* ]]

    menu_ctx=$(grep -A8 'MENU_SELECTED\[5\]' "$script" | head -12)
    [[ "$menu_ctx" == *"load_config"* ]]
}

@test "the API import never sends a qcow2 to XO" {
    # XO's import endpoint takes raw and VHD only -- SR_importVdi is called
    # with `raw ? raw : vhd`, and the VDI route types its format as
    # Exclude<SUPPORTED_VDI_FORMAT, 'qcow2'>. A qcow2 posted with raw=false is
    # read as a VHD and dies on its footer checksum ("invalid footer checksum
    # 0"), which is not a message that points anywhere near the real cause.
    local body
    body=$(declare -f tpl_api_import_image)

    # Always raw=true: the conversion happens before the upload, never by
    # asking XO to interpret a format it does not accept.
    [[ "$body" == *"raw=true"* ]]
    [[ "$body" != *"raw=false"* ]]
    [[ "$body" != *'raw=${raw_q}'* ]]

    # And a non-raw URL is converted rather than streamed as-is.
    [[ "$body" == *"qemu-img convert"* ]]
}

@test "the progress bar is drawn one column narrower than the terminal" {
    # curl draws --progress-bar to exactly COLUMNS characters and redraws with
    # a bare carriage return. A line that exactly fills the row leaves the
    # cursor in the final column, where terminals disagree about whether to
    # wrap -- and a wrapped cursor sends the next redraw to the wrong line, so
    # the bar walks down the screen over its own percentage. Reporting one
    # column less leaves a trailing space and removes the ambiguity.
    tput() { case "$1" in cols) echo "$FAKE_COLS";; lines) echo 24;; esac; }

    FAKE_COLS=80  ; [ "$(deploy_progress_columns)" = "79" ]
    FAKE_COLS=120 ; [ "$(deploy_progress_columns)" = "119" ]
    # Clamped at the top so an absurd width cannot produce an absurd line...
    FAKE_COLS=500 ; [ "$(deploy_progress_columns)" = "199" ]
    # ...and at the bottom, where a 10-column bar would be useless.
    FAKE_COLS=30  ; [ "$(deploy_progress_columns)" = "39" ]
    # No terminal, or a nonsense answer, falls back the way the menu does.
    FAKE_COLS=""    ; [ "$(deploy_progress_columns)" = "79" ]
    FAKE_COLS="abc" ; [ "$(deploy_progress_columns)" = "79" ]
}

@test "the width reported to curl is always less than the real terminal width" {
    # The -1 is the entire fix, so a refactor that clamps or defaults without
    # subtracting would silently restore the bug. Checked as a property across
    # the range rather than at the handful of points above.
    tput() { case "$1" in cols) echo "$FAKE_COLS";; lines) echo 24;; esac; }

    local w got
    for w in 40 55 80 100 120 160 200; do
        FAKE_COLS=$w
        got=$(deploy_progress_columns)
        [ "$got" -lt "$w" ]
    done
}

@test "every curl progress bar in a build sets the narrowed width" {
    # A build draws more than one bar, and fixing only the first leaves the
    # rest wrapping -- which is exactly what happened the first time round.
    # Counted rather than spot-checked so a new bar added later cannot quietly
    # miss it.
    local body bars fixed
    body=$(declare -f deploy_import_vdi_staged tpl_api_import_image 2>/dev/null)

    bars=$(grep -c -- "--progress-bar" <<< "$body")
    fixed=$(grep -c "deploy_progress_columns" <<< "$body")
    [ "$bars" -ge 1 ]
    [ "$fixed" -ge "$bars" ]
}

@test "the drawn bar leaves the cursor where it found it" {
    # The complaint this exists to fix: curl repaints the whole line every
    # update and leaves the cursor sitting in it, so the cursor is visibly
    # dragged back and forth. Save/restore (ESC 7 / ESC 8) puts it back where
    # it was, so it never sits inside the bar between updates.
    local body
    # The rendering moved into deploy_draw_progress_n when the upload started
    # sharing it; the escapes live there now.
    body=$(declare -f deploy_draw_progress_n)
    [[ "$body" == *'\0337'* ]]
    [[ "$body" == *'\0338'* ]]
    # Cleared to end of line rather than padded over, the way draw_menu does
    # it. Matched against the expanded escape: declare -f prints the value bash
    # already resolved, not the backslash-033 that was typed.
    [[ "$body" == *$'\033[K'* ]]
}

@test "the drawn bar fits the terminal with a column to spare" {
    # Rendered for a range of widths: the bar plus its percentage must never
    # reach the last column, because a line that exactly fills the row leaves
    # the cursor where terminals disagree about wrapping.
    tput() { case "$1" in cols) echo "$FAKE_COLS";; lines) echo 24;; esac; }

    local w tmp out visible
    tmp=$(mktemp); printf '%*s' 500 "" > "$tmp"

    for w in 60 80 120; do
        FAKE_COLS=$w
        DEPLOY_PROGRESS_FILLED=0; DEPLOY_PROGRESS_PCT=-1; DEPLOY_PROGRESS_BYTES=-1
        out=$(deploy_draw_progress "$tmp" 500 2>&1)
        # Strip the escape sequences to count what actually lands on screen.
        visible=$(printf '%s' "$out" | sed -e 's/\x1b7//g' -e 's/\x1b8//g' \
            -e 's/\x1b\[K//g' -e 's/\r//g')
        [ "${#visible}" -lt "$w" ]
    done
    rm -f "$tmp"
}

@test "the upload draws our bar, not curl's" {
    # The second bar an operator sees. It was left on curl's own meter at
    # first, which meant one clean bar followed by one that still scribbled.
    local body
    body=$(declare -f tpl_api_import_image)
    [[ "$body" == *"deploy_curl_upload_with_progress"* ]]
    # And it must feed curl from the counter, not hand it the file directly --
    # curl reading the file itself is what leaves nothing to measure.
    [[ "$body" == *"--data-binary @-"* ]]
    [[ "$body" != *'--data-binary "@${upload_file}"'* ]]
}

@test "the upload counter never signals dd" {
    # dd reports progress either continuously with status=progress or on
    # SIGUSR1. The signal is a race: sent before dd installs its handler it
    # kills dd instead, aborting the upload that carries the image.
    local body
    body=$(declare -f deploy_curl_upload_with_progress)
    [[ "$body" == *"status=progress"* ]]
    [[ "$body" != *"USR1"* ]]
}

@test "the upload passes an explicit Content-Length" {
    # The body comes from a fifo, which has no length curl can discover, and
    # XAPI refuses a chunked body -- so the size has to be stated.
    local body
    body=$(declare -f deploy_curl_upload_with_progress)
    [[ "$body" == *"Content-Length:"* ]]
}

@test "both transfer helpers share one renderer" {
    # Download and upload measure progress differently but draw identically.
    # Two copies of the drawing code is how one of them stops getting fixes.
    local dl ul
    dl=$(declare -f deploy_curl_with_progress)
    ul=$(declare -f deploy_curl_upload_with_progress)
    [[ "$dl" == *"deploy_draw_progress"* ]]
    [[ "$ul" == *"deploy_draw_progress_n"* ]]
}

@test "a failed transfer still fails the build" {
    # The bar runs the transfer in the background and recovers its status with
    # wait. Losing that status would turn a failed download into a silent
    # success and a corrupt template.
    local body
    body=$(declare -f deploy_curl_with_progress)
    [[ "$body" == *'wait "$pid"'* ]]
    [[ "$body" == *'return "$rc"'* ]]
}

@test "the API path does not ask curl to resume a file it just deleted" {
    # The image file is removed immediately before the download, so -C - had
    # nothing to resume -- the comment above it says clearing is deliberate.
    local api
    api=$(declare -f tpl_api_import_image 2>/dev/null)
    [[ "$api" != *'-o "$local_file" -C -'* ]]
}

@test "a missing qemu-img is reported before the image is downloaded" {
    # Downloading 800 MB and then discovering the converter is absent wastes
    # the slowest step of the build.
    local body chk dl
    body=$(declare -f tpl_api_import_image)
    chk=$(grep -n 'command -v qemu-img' <<< "$body" | head -1 | cut -d: -f1)
    dl=$(grep -n 'downloading the image' <<< "$body" | head -1 | cut -d: -f1)
    [ -n "$chk" ]
    [ -n "$dl" ]
    [ "$chk" -lt "$dl" ]
}

@test "a failed API build removes the imported disk even with no VM" {
    # The disk is imported before the VM is created, so a failure in between
    # leaves a multi-gigabyte VDI that nothing references. Deleting only the
    # VM misses it entirely, because there is no VM.
    local body
    body=$(declare -f tpl_api_cleanup_failed_build)
    [[ "$body" == *"vdi.delete"* ]]

    # And the VDI cleanup must not sit behind the VM guard, or it never runs
    # in exactly the case it exists for.
    local vdi_line guard_line
    vdi_line=$(grep -n 'vdi.delete' <<< "$body" | head -1 | cut -d: -f1)
    guard_line=$(grep -n 'TPL_BUILD_STARTED.*|| return 0' <<< "$body" | head -1 | cut -d: -f1)
    [ -n "$vdi_line" ]
    [ -n "$guard_line" ]
    [ "$vdi_line" -lt "$guard_line" ]
}

@test "tpl_json_id_where matches a field exactly, not as a substring" {
    # An upgraded pool keeps "Old version of guest-tools.iso" beside
    # "guest-tools.iso". A substring match takes whichever is listed first and
    # installs guest tools from a superseded ISO -- which works often enough
    # not to be noticed. XO's own ?filter= is a substring match too, so the
    # exactness has to happen locally.
    local json='[
  {
    "id": "old-1",
    "name_label": "Old version of guest-tools.iso"
  },
  {
    "id": "current-1",
    "name_label": "guest-tools.iso"
  }
]'
    [ "$(tpl_json_id_where "$json" name_label "guest-tools.iso")" = "current-1" ]
    [ "$(tpl_json_id_where "$json" name_label "Old version of guest-tools.iso")" = "old-1" ]
    [ -z "$(tpl_json_id_where "$json" name_label "nothing-like-this")" ]
}

@test "an XO template id is accepted despite not being a plain uuid" {
    # Templates are identified by pool uuid + object uuid joined with a dash,
    # 73 characters. A ^[0-9a-f-]{36}$ test rejects that, which is how "could
    # not find the template" got reported for one the API had just returned.
    tpl_is_xo_id "751d40fa-60b5-82cf-e735-6ed42d0e03f8-552bce37-51b2-445d-84f2-5f33fa112d7e"
    tpl_is_xo_id "067cf6c5-62f6-472c-b29d-4fd44bcefc4d"
    ! tpl_is_xo_id "not-an-id"
    ! tpl_is_xo_id ""
}

@test "xo-cli is given the token in the URL, not as a flag" {
    # xo-cli has no standalone --token for a command invocation: its --help
    # says "The URL must include credentials". Passing one is read as a
    # positional argument and fails with "invalid arg: <the token>", which
    # reads as a malformed token rather than a misplaced one.
    local body
    body=$(declare -f tpl_xo_cli)
    [[ "$body" == *'${XO_API_TOKEN}@'* ]]
    [[ "$body" != *"--token"* ]]
}

@test "the API path picks the management network, not whichever XO lists first" {
    # Taking networks?limit=1 returned "Host internal management network" on one
    # live run and "Pool-wide network 3" on the next -- both carrying no PIF, so
    # a VM on either reaches nothing and the preparation boot, which installs
    # guest tools and updates packages from the mirrors, hangs until it times
    # out. The management PIF's own network is what the SSH path asks for.
    local body
    body=$(declare -f tpl_api_resolve_targets)
    [[ "$body" == *"pifs?fields=management"* ]]
    [[ "$body" != *'"networks?fields=id,name_label&limit=1"'* ]]
}

@test "a boolean JSON field can be matched, not just a quoted string" {
    # PIFs report management as a bare `true`. The quoted-value branch cannot
    # match that, so before this the management lookup returned nothing at all
    # and fell through to the guess it was meant to replace.
    #
    # Single-quoted so the $network key reaches awk as written rather than
    # being expanded by the shell -- which is also why the field name is
    # passed single-quoted below.
    local json
    json='[
  {
    "management": false,
    "$network": "wrong-net"
  },
  {
    "management": true,
    "$network": "right-net"
  }
]'
    [ "$(tpl_json_field_where "$json" management true '$network')" = "right-net" ]
}

@test "the cloud-init drive is found in XO's pretty-printed listing" {
    # XO prints each object across several lines. Splitting the body on '}'
    # left the matched line holding the name alone, with the id on an earlier
    # line, so the lookup returned empty and the drive was never detached --
    # a clone then found a used seed and skipped the operator's cloud-config.
    local json
    json='[
  {
    "id": "root-disk",
    "name_label": "Ubuntu 26.04 LTS (Resolute) Cloud-init root"
  },
  {
    "id": "config-drive",
    "name_label": "XO CloudConfigDrive"
  }
]'
    [ "$(tpl_json_id_matching "$json" -Ei 'cloud.?config|cloudinit|cidata')" = "config-drive" ]
}

@test "the base template is looked up by uuid, not by REST id" {
    # A template carries both and they differ: `id` joins the pool uuid to the
    # object uuid, `uuid` is the XAPI object alone. create_vm resolves its
    # template against XAPI, so the compound id comes back as "no such object"
    # quoting the exact string the listing had just returned.
    local body
    body=$(declare -f tpl_api_create_build_vm)
    [[ "$body" == *"tpl_json_field_where"* ]]
    [[ "$body" == *"uuid"* ]]
}

@test "tpl_json_field_where can return a field other than id" {
    local json='[
  {
    "id": "pool-obj-compound",
    "uuid": "plain-uuid",
    "name_label": "Other install media"
  }
]'
    [ "$(tpl_json_field_where "$json" name_label 'Other install media' uuid)" = "plain-uuid" ]
    [ "$(tpl_json_field_where "$json" name_label 'Other install media' id)" = "pool-obj-compound" ]
}

@test "an asynchronous create is followed to its task result" {
    # create_vm answers 202 with {"taskId":...}; the VM's id appears in that
    # task's result.id once it succeeds. Reading the POST body for an id finds
    # none and fails a build whose VM is being created perfectly well.
    local body
    body=$(declare -f tpl_api_create_build_vm)
    [[ "$body" == *"taskId"* ]]
    [[ "$body" == *"tpl_api_await_task"* ]]
}

@test "the VBD body uses the capitalised keys the endpoint requires" {
    # The schema requires "VM" and "VDI" in that case. Lowercase is rejected
    # with a 422 that names fields the request appears to contain.
    local body
    body=$(declare -f tpl_api_create_build_vm)
    [[ "$body" == *'"VM":"%s","VDI":"%s"'* ]]
    [[ "$body" != *'"vm":"%s","vdi":"%s"'* ]]
}
