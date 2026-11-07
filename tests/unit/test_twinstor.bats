#!/usr/bin/env bats
# Tests for the TwinStor functions (ts_*) in install-xen-orchestra.sh.
#
# Nothing here reaches a real host. The pure helpers are called directly, the
# pool is faked by replacing dom0_exec / dom0_xe / ts_exec, the remote install
# script runs locally against stub wget, and the expect script that answers the
# second host's prompts runs against a fake `ssh` placed first in PATH.

setup() {
    load '../helpers/mock_helpers'
    load_script

    WORK="${BATS_TEST_TMPDIR}"
    DEPLOY_WORKDIR="${WORK}/work"
    mkdir -p "$DEPLOY_WORKDIR" "${WORK}/bin"
    TWINSTOR_VERSION=0.7.4
    TWINSTOR_SHA256=0122a43a1b07bb253a33e5ec1b947a0eb9490ecbc83347585eeed804c20679f4
    NON_INTERACTIVE=false
    DRY_RUN=false
}

# --- pin and path validation ---------------------------------------------------

@test "ts_check_pin accepts the shipped pin" {
    run ts_check_pin
    [ "$status" -eq 0 ]
}

@test "ts_check_pin rejects a malformed version" {
    TWINSTOR_VERSION='0.7.4; rm -rf /'
    run ts_check_pin
    [ "$status" -eq 1 ]
    [[ "$output" == *"TWINSTOR_VERSION"* ]]
}

@test "ts_check_pin rejects a short or upper-case hash" {
    TWINSTOR_SHA256=abc
    run ts_check_pin
    [ "$status" -eq 1 ]
    TWINSTOR_SHA256=0122A43A1B07BB253A33E5EC1B947A0EB9490ECBC83347585EEED804C20679F4
    run ts_check_pin
    [ "$status" -eq 1 ]
}

@test "the bundle URL is built from the version" {
    run ts_bundle_url
    [ "$output" = "https://github.com/vatesfr/twinstor/releases/download/v0.7.4/twinstor-test-0.7.4.tar.gz" ]
}

@test "ts_valid_device accepts by-id and zvol paths" {
    ts_valid_device /dev/sdb
    ts_valid_device /dev/disk/by-id/ata-ST4000_ZDH1234
    ts_valid_device /dev/zvol/tank/twinstor
    ts_valid_device /dev/md0
}

@test "ts_valid_device rejects anything a shell could read as more" {
    run ts_valid_device "/dev/sdb; reboot"
    [ "$status" -eq 1 ]
    run ts_valid_device "/dev/sdb'"
    [ "$status" -eq 1 ]
    run ts_valid_device '/dev/$(id)'
    [ "$status" -eq 1 ]
    run ts_valid_device "/dev/../etc/passwd"
    [ "$status" -eq 1 ]
    run ts_valid_device "sdb"
    [ "$status" -eq 1 ]
}

# --- parsing -------------------------------------------------------------------

@test "ts_dom0_required_mib follows 1 GiB + 16 MiB per VM + 30%" {
    run ts_dom0_required_mib 0
    [ "$output" = "1331" ]
    run ts_dom0_required_mib 100
    [ "$output" = "3411" ]
}

@test "ts_status_ok accepts status --plain" {
    ts_status_ok $'topology\tfate-shared\nhealth\thealthy\nreadiness\tready\nreadiness_reason\t'
}

@test "ts_status_ok rejects a degraded --plain status" {
    run ts_status_ok $'health\tdegraded\nreadiness\tserving-without-redundancy'
    [ "$status" -eq 1 ]
    run ts_status_ok $'health\thealthy\nreadiness\tnot-ready\nreadiness_reason\tready soon'
    [ "$status" -eq 1 ]
}

@test "ts_status_ok accepts both status layouts" {
    ts_status_ok $'# health: healthy (serving, peer redundant)\n\n[OK] readiness:   ready (local serving, peer redundant)'
    ts_status_ok $'● healthy: serving, peer redundant\n  ✓ readiness:   ready (local serving, peer redundant)'
}

@test "ts_status_ok rejects an unhealthy or not-ready host" {
    run ts_status_ok $'health: unhealthy\nreadiness: ready'
    [ "$status" -eq 1 ]
    run ts_status_ok $'health: healthy\nreadiness: serving-without-redundancy'
    [ "$status" -eq 1 ]
    run ts_status_ok $'health: healthy\nreadiness: not-ready'
    [ "$status" -eq 1 ]
    run ts_status_ok ""
    [ "$status" -eq 1 ]
}

@test "ts_help_has_flag matches whole flags only" {
    local help=$'  --peer-ip IP\n  --backing-device DEV\n  --yes-all  something else'
    ts_help_has_flag "$help" --peer-ip
    ts_help_has_flag "$help" --backing-device
    run ts_help_has_flag "$help" --yes
    [ "$status" -eq 1 ]
}

@test "ts_setup_flags_present needs the three flags Vates documents" {
    ts_setup_flags_present $'--peer-ip IP\n--backing-device DEV\n--yes  skip prompts'
    run ts_setup_flags_present $'--peer-ip IP\n--backing-device DEV'
    [ "$status" -eq 1 ]
}

@test "ts_upgrade_notes warns about 0.6.x to 0.7.x, and is silent for a same-version bundle" {
    run ts_upgrade_notes 0.6.9 0.7.4
    [[ "$output" == *"back to back"* ]]
    run ts_upgrade_notes 0.7.4 0.7.4
    [ -z "$output" ]
}

# --- operation guards ----------------------------------------------------------

@test "TwinStor refuses --non-interactive" {
    NON_INTERACTIVE=true
    run ts_session_start
    [ "$status" -eq 1 ]
    [[ "$output" == *"--non-interactive"* ]]
}

@test "TwinStor stops under --dry-run without connecting" {
    DRY_RUN=true
    deploy_connect_pool_master() { echo CONNECTED; }
    run ts_session_start
    [ "$status" -eq 1 ]
    [[ "$output" == *"DRY-RUN"* ]]
    [[ "$output" != *CONNECTED* ]]
}

@test "TwinStor refuses to start with a bad pin, before connecting" {
    TWINSTOR_SHA256=nothex
    deploy_connect_pool_master() { echo CONNECTED; }
    run ts_session_start
    [ "$status" -eq 1 ]
    [[ "$output" != *CONNECTED* ]]
}

@test "TwinStor ends column 1, so every other item keeps its place in the grid" {
    # 13 items: column 1 is the first 7, column 2 the last 6.
    [ "$MENU_TOTAL" -eq 13 ]
    [ "$MENU_LEFT_COUNT" -eq 7 ]
    [ "${MENU_NAMES[5]}" = "VM Template Library" ]
    [ "${MENU_NAMES[6]}" = "TwinStor" ]
    # column 2 starts with Reconfigure and ends with Custom Plugins, as before
    [ "${MENU_NAMES[7]}" = "Reconfigure Xen Orchestra" ]
    [ "${MENU_NAMES[12]}" = "Custom Plugins" ]
}

# --- pool discovery and preflight, against a faked pool --------------------------

fake_pool() {
    # Arguments: host count, product version for every host
    FAKE_HOSTS=$1
    FAKE_VERSION=${2:-8.3.0}
    FAKE_REL_B="xcp-ng-release-8.3.0-1"
    FAKE_UNPLUGGED=""
    POOL_MASTER_IP=10.0.0.1
    HOST_USERNAME=root
    TS_HOST_UUIDS=(u1 u2 u3); TS_HOST_NAMES=(h1 h2 h3); TS_HOST_IPS=(10.0.0.1 10.0.0.2 10.0.0.3)
    TS_HOST_UUIDS=("${TS_HOST_UUIDS[@]:0:$1}")
    TS_HOST_NAMES=("${TS_HOST_NAMES[@]:0:$1}")
    TS_HOST_IPS=("${TS_HOST_IPS[@]:0:$1}")
    dom0_xe() {
        case "$1" in
            *product_version*) echo "$FAKE_VERSION" ;;
            "pbd-list currently-attached=false"*) echo "$FAKE_UNPLUGGED" ;;
            "vm-list"*) echo "a,b,c" ;;
            "pool-list params=master"*) echo u1 ;;
        esac
    }
    ts_exec_script() {
        local rel="xcp-ng-release-8.3.0-1"
        [[ "$1" == "10.0.0.2" ]] && rel="$FAKE_REL_B"
        printf 'mem_kb=8388608\ntwinstor=\nrelease=%s\nxapi=xapi-core-1\nxen=xen-hypervisor-4\n' "$rel"
    }
    ts_count_vms() { echo 3; }
}

@test "preflight passes on two matching 8.3 hosts" {
    fake_pool 2
    run ts_preflight
    [ "$status" -eq 0 ]
    [[ "$output" == *"same patch level"* ]]
}

@test "preflight refuses a pool of three" {
    fake_pool 3
    run ts_preflight
    [ "$status" -eq 1 ]
    [[ "$output" == *"exactly two"* ]]
}

@test "preflight refuses XCP-ng older than 8.3" {
    fake_pool 2 8.2.1
    run ts_preflight
    [ "$status" -eq 1 ]
    [[ "$output" == *"8.3"* ]]
}

@test "preflight refuses hosts at different patch levels" {
    fake_pool 2
    FAKE_REL_B="xcp-ng-release-8.3.0-9"
    run ts_preflight
    [ "$status" -eq 1 ]
    [[ "$output" == *"patch level"* ]]
}

@test "preflight refuses a pool with an unplugged SR" {
    fake_pool 2
    FAKE_UNPLUGGED="sr-uuid-1"
    run ts_preflight
    [ "$status" -eq 1 ]
    [[ "$output" == *"not plugged"* ]]
}

@test "preflight warns when dom0 memory is below the rule of thumb" {
    fake_pool 2
    ts_count_vms() { echo 1000; }
    prompt_yes_no() { return 1; }
    run ts_preflight
    [ "$status" -eq 0 ]
    [[ "$output" == *"rule of thumb"* ]]
}

@test "ts_discover_hosts reads the hosts and finds the master" {
    POOL_MASTER_IP=10.0.0.1
    HOST_USERNAME=root
    dom0_exec() { printf 'u1|h1|10.0.0.1\nu2|h2|10.0.0.2\n'; }
    dom0_xe() { echo u2; }
    ts_pin_host_key() { : > "${DEPLOY_WORKDIR}/known_hosts_$1"; echo pinned >> "${DEPLOY_WORKDIR}/known_hosts_$1"; }
    ts_ssh() { return 0; }
    ts_discover_hosts
    [ "${#TS_HOST_IPS[@]}" -eq 2 ]
    [ "$TS_MASTER_IDX" -eq 1 ]
    # the master is reached by the address that was typed
    [ "${TS_HOST_IPS[1]}" = "10.0.0.1" ]
}

# --- the script that runs on each host --------------------------------------------

@test "the remote scripts are valid shell" {
    run bash -n <(ts_install_script)
    [ "$status" -eq 0 ]
    run bash -n <(ts_disk_candidates_script)
    [ "$status" -eq 0 ]
    run bash -n <(ts_host_facts_script)
    [ "$status" -eq 0 ]
}

make_bundle() {
    local ver=$1 src="${WORK}/src/twinstor-test-${1}"
    mkdir -p "$src"
    printf '#!/bin/sh\necho INSTALL-RAN\n' > "${src}/install.sh"
    chmod +x "${src}/install.sh"
    tar czf "${WORK}/bundle.tar.gz" -C "${WORK}/src" "twinstor-test-${ver}"
    BUNDLE_SHA=$(sha256sum "${WORK}/bundle.tar.gz" | cut -d' ' -f1)
    cat > "${WORK}/bin/wget" <<STUB
#!/bin/bash
# wget -q -O <name> <url>
cp "${WORK}/bundle.tar.gz" "\$3"
STUB
    chmod +x "${WORK}/bin/wget"
}

@test "the install script verifies the hash, then runs install.sh" {
    make_bundle 0.7.4
    run env PATH="${WORK}/bin:$PATH" TS_INSTALL_DIR="${WORK}/inst" \
        bash <(ts_install_script) 0.7.4 https://example.invalid/x.tar.gz "$BUNDLE_SHA"
    [ "$status" -eq 0 ]
    [[ "$output" == *"sha256 ok"* ]]
    [[ "$output" == *"INSTALL-RAN"* ]]
}

@test "the install script stops on a hash mismatch and never runs install.sh" {
    make_bundle 0.7.4
    run env PATH="${WORK}/bin:$PATH" TS_INSTALL_DIR="${WORK}/inst" \
        bash <(ts_install_script) 0.7.4 https://example.invalid/x.tar.gz \
        0000000000000000000000000000000000000000000000000000000000000000
    [ "$status" -eq 23 ]
    [[ "$output" == *"mismatch"* ]]
    [[ "$output" != *"INSTALL-RAN"* ]]
    [ ! -e "${WORK}/inst/twinstor-test-0.7.4.tar.gz" ]
}

@test "ts_install_bundle explains a hash mismatch" {
    TS_HOST_IPS=(10.0.0.1); TS_HOST_NAMES=(h1)
    ts_exec_script() { echo "ts-error: SHA-256 mismatch" >&2; return 23; }
    run ts_install_bundle 0
    [ "$status" -eq 1 ]
    [[ "$output" == *"did not match the published SHA-256"* ]]
}


# --- the sub-menu ------------------------------------------------------------------------

menu_stubs() {
    deploy_connect_pool_master() { echo CONNECTED; }
    ts_discover_hosts() { return 0; }
    ts_deploy() { echo RAN-INSTALL; }
    ts_op_upgrade() { echo RAN-UPDATE; }
    ts_op_status() { echo RAN-STATUS; }
    ts_op_support_bundle() { echo RAN-BUNDLE; }
    DEPLOY_WORKDIR=""
    # ts_session_start checks that the ssh tools exist; a machine without an
    # openssh client must not fail these tests.
    local t
    for t in ssh ssh-keygen ssh-keyscan; do
        [[ -x "${WORK}/bin/$t" ]] || { printf '#!/bin/sh\nexit 0\n' > "${WORK}/bin/$t"; chmod +x "${WORK}/bin/$t"; }
    done
    PATH="${WORK}/bin:$PATH"
}

@test "the sub-menu offers install, update, status, support bundle and back" {
    menu_stubs
    deploy_choose() { printf '%s\n' "$@" > "${WORK}/offered"; DEPLOY_CHOICE=back; }
    run twinstor_menu
    [ "$status" -eq 0 ]
    run cat "${WORK}/offered"
    [[ "$output" == *"install|"* ]]
    [[ "$output" == *"update|"* ]]
    [[ "$output" == *"status|"* ]]
    [[ "$output" == *"bundle|"* ]]
    [[ "$output" == *"back|"* ]]
    # exactly those: the prompt line plus five entries
    [ "${#lines[@]}" -eq 6 ]
}

@test "choosing Back never connects to the pool" {
    menu_stubs
    deploy_choose() { DEPLOY_CHOICE=back; }
    run twinstor_menu
    [ "$status" -eq 0 ]
    [[ "$output" != *CONNECTED* ]]
}

@test "each sub-menu choice runs its operation after connecting" {
    menu_stubs
    local pair
    for pair in install:RAN-INSTALL update:RAN-UPDATE status:RAN-STATUS bundle:RAN-BUNDLE; do
        deploy_choose() { DEPLOY_CHOICE="${pair%%:*}"; }
        run twinstor_menu
        [ "$status" -eq 0 ]
        [[ "$output" == *CONNECTED* ]]
        [[ "$output" == *"${pair#*:}"* ]]
    done
}

@test "twinstor_menu update skips the menu (--twinstor-upgrade)" {
    menu_stubs
    deploy_choose() { echo MENU-SHOWN; DEPLOY_CHOICE=back; }
    run twinstor_menu update
    [[ "$output" != *MENU-SHOWN* ]]
    [[ "$output" == *RAN-UPDATE* ]]
}

@test "the sub-menu is not shown under --dry-run" {
    menu_stubs
    DRY_RUN=true
    deploy_choose() { echo MENU-SHOWN; DEPLOY_CHOICE=back; }
    run twinstor_menu
    [ "$status" -eq 0 ]
    [[ "$output" != *MENU-SHOWN* ]]
    [[ "$output" == *DRY-RUN* ]]
}

# --- the CHAP password -------------------------------------------------------------------

@test "ts_new_chap_password is 16 hex characters and differs each time" {
    local a b
    a=$(ts_new_chap_password)
    b=$(ts_new_chap_password)
    [[ "$a" =~ ^[0-9a-f]{16}$ ]]
    [[ "$b" =~ ^[0-9a-f]{16}$ ]]
    [ "$a" != "$b" ]
}

@test "ts_redact hides the generated password and any CHAP line from the hosts" {
    TS_CHAP=0123456789abcdef
    local out
    out=$(printf 'x 0123456789abcdef y\nrun with --chap-password '"'"'Zx9abc'"'"'\n  CHAP password:  Hq7Lm2\n' | ts_redact)
    [[ "$out" != *0123456789abcdef* ]]
    [[ "$out" != *Zx9abc* ]]
    [[ "$out" != *Hq7Lm2* ]]
    [[ "$out" == *"<hidden>"* ]]
}

# --- the setup commands --------------------------------------------------------------------

setup_fixture() {
    TS_HOST_IPS=(10.0.0.1 10.0.0.2); TS_HOST_NAMES=(h1 h2)
    TS_DEVICES=(/dev/disk/by-id/ata-A /dev/disk/by-id/ata-B-part2)
    TS_TOPOLOGY=fate-shared; TS_DIRECT_IPS=(); TS_PING_TARGETS=""
    TS_CHAP=0123456789abcdef
}

@test "each host is set up against its peer with the documented flags and the same CHAP password" {
    setup_fixture
    run ts_setup_command 0
    [ "$output" = "twinstor setup --peer-ip 10.0.0.2 --backing-device /dev/disk/by-id/ata-A --chap-password 0123456789abcdef --yes" ]
    run ts_setup_command 1
    [ "$output" = "twinstor setup --peer-ip 10.0.0.1 --backing-device /dev/disk/by-id/ata-B-part2 --chap-password 0123456789abcdef --yes" ]
}

@test "a partition is passed to setup as its by-id name" {
    setup_fixture
    run ts_setup_command 1
    [[ "$output" == *"--backing-device /dev/disk/by-id/ata-B-part2"* ]]
}

@test "arbitrated mode gives each host the PEER's end of the direct link" {
    setup_fixture
    TS_TOPOLOGY=arbitrated; TS_DIRECT_IPS=(10.99.99.1 10.99.99.2)
    run ts_setup_command 0
    [[ "$output" == *"--direct-ip 10.99.99.2"* ]]
    run ts_setup_command 1
    [[ "$output" == *"--direct-ip 10.99.99.1"* ]]
}

@test "extra tie-breakers become --ping-target flags on both hosts" {
    setup_fixture
    TS_PING_TARGETS="192.168.1.5 192.168.1.6"
    run ts_setup_command 0
    [[ "$output" == *"--ping-target 192.168.1.5 --ping-target 192.168.1.6"* ]]
    run ts_setup_command 1
    [[ "$output" == *"--ping-target 192.168.1.5 --ping-target 192.168.1.6"* ]]
}

# --- choosing how to run setup --------------------------------------------------------------

ALL_FLAGS=$'--peer-ip IP\n--backing-device DEV\n--chap-password PW\n--ping-target IP\n--direct-ip IP\n--yes'

@test "fate-shared with the documented flags is scripted" {
    setup_fixture
    ts_exec() { printf '%s\n' "$ALL_FLAGS"; }
    ts_choose_setup_mode
    [ "$TS_ATTENDED" = "false" ]
}

@test "a build without a needed flag runs the wizard by hand" {
    setup_fixture
    ts_exec() { printf -- '--peer-ip\n--backing-device\n--yes\n'; }
    run ts_choose_setup_mode
    [[ "$output" == *"--chap-password"* ]]
    ts_choose_setup_mode >/dev/null
    [ "$TS_ATTENDED" = "true" ]
}

@test "arbitrated is scripted once the direct link already has its address on both hosts" {
    setup_fixture
    TS_TOPOLOGY=arbitrated; TS_DIRECT_IPS=(10.99.99.1 10.99.99.2)
    ts_exec() {
        case "$2" in
            "twinstor setup --help") printf '%s\n' "$ALL_FLAGS" ;;
            *) return 0 ;;   # the address is configured
        esac
    }
    ts_choose_setup_mode
    [ "$TS_ATTENDED" = "false" ]
}

@test "arbitrated runs the wizard by hand while the direct link has no address" {
    setup_fixture
    TS_TOPOLOGY=arbitrated; TS_DIRECT_IPS=(10.99.99.1 10.99.99.2)
    ts_exec() {
        case "$2" in
            "twinstor setup --help") printf '%s\n' "$ALL_FLAGS" ;;
            *) return 1 ;;   # the address is not configured
        esac
    }
    run ts_choose_setup_mode
    [[ "$output" == *"not configured"* ]]
    ts_choose_setup_mode >/dev/null
    [ "$TS_ATTENDED" = "true" ]
}

# --- scripted setup: the order matters ------------------------------------------------------------

@test "the second host is not started until the first says Action required" {
    setup_fixture
    : > "${WORK}/calls"
    ts_exec() {
        case "$1" in
            10.0.0.1)
                echo "starting host 1" 
                sleep 0
                echo "  Action required: now set up the other node (h2)"
                echo "first host done" ;;
            10.0.0.2)
                # by the time the second host is run, the first must have printed it
                grep -q 'Action required' "${DEPLOY_WORKDIR}/setup_host0.log" && echo "second host started after the first was ready" ;;
        esac
    }
    sleep() { :; }
    run ts_run_setup_scripted
    [ "$status" -eq 0 ]
    [[ "$output" == *"second host started after the first was ready"* ]]
}

@test "scripted setup stops, with the password hidden, when the first host fails before it is ready" {
    setup_fixture
    ts_exec() { echo "no partition tiebreaker: no default gateway detected, chap 0123456789abcdef"; return 1; }
    sleep() { :; }
    run ts_run_setup_scripted
    [ "$status" -eq 1 ]
    [[ "$output" == *"stopped before it was ready"* ]]
    [[ "$output" == *"no partition tiebreaker"* ]]
}

@test "scripted setup never prints the CHAP password" {
    setup_fixture
    ts_exec() {
        case "$1" in
            10.0.0.1) echo "  Action required: now set up the other node"; echo "CHAP password:  $(ts_setup_command 0 | grep -o '[0-9a-f]\{16\}')" ;;
            *) echo "second host ok" ;;
        esac
    }
    ts_new_chap_password() { echo 0123456789abcdef; }
    sleep() { :; }
    run ts_run_setup_scripted
    [ "$status" -eq 0 ]
    [[ "$output" != *0123456789abcdef* ]]
}

# --- which disks and partitions are offered --------------------------------------------------------

# A fake host: lsblk, findmnt, blockdev and pvs answer from a fixture, and
# /sys/block and /dev/disk/by-id are directories under the test's temp dir.
disks_fixture() {
    local d="${WORK}/hostfs"
    mkdir -p "${d}/sys" "${d}/byid"
    # NAME|TYPE|PARENT|MOUNT|MODEL|SERIAL|PARTLABEL
    cat > "${WORK}/disks.txt" <<'FX'
/dev/sda|disk||||SYS1|
/dev/sda1|part|/dev/sda|/||SYS1|
/dev/sda2|part|/dev/sda|||SYS1|twinstor-data
/dev/sda3|part|/dev/sda|||SYS1|
/dev/sdb|disk|||MODB|SERB|
/dev/sdc|disk|||MODC|SERC|
/dev/sdc1|part|/dev/sdc|||SERC|
/dev/sdc2|part|/dev/sdc|/data||SERC|
/dev/sdd|disk|||MODD|SERD|
/dev/md0|raid1|/dev/sdd|||
/dev/sde|disk|||MODE|SERE|
/dev/sdf|disk|||MODF|SERF|
/dev/sdg|disk|||MODG|SERG|
/dev/sdg1|part|/dev/sdg|||SERG|
FX
    local n
    for n in sda sdb sdc sdd sde sdf sdg; do
        mkdir -p "${d}/sys/${n}"; echo 0 > "${d}/sys/${n}/ro"
    done
    echo 1 > "${d}/sys/sdf/ro"
    printf '/dev/sde\n/dev/sdg1\n' > "${WORK}/pvs.txt"
    ln -s /dev/sdb  "${d}/byid/ata-MODB_SERB"
    ln -s /dev/sdc1 "${d}/byid/ata-MODC_SERC-part1"
    ln -s /dev/sda2 "${d}/byid/wwn-0x5000"
    ln -s /dev/sda2 "${d}/byid/scsi-3500"

    cat > "${WORK}/bin/lsblk" <<'STUB'
#!/bin/bash
fx="$LSBLK_FIXTURE"; cols=""; dev=""; flags=""
while [ $# -gt 0 ]; do
    case "$1" in -o) cols=$2; shift 2 ;; -*) flags+="$1 "; shift ;; *) dev=$1; shift ;; esac
done
field() { awk -F'|' -v n="$1" -v i="$2" '$1==n{print $i}' "$fx"; }
children() { awk -F'|' -v p="$1" '$3==p{print $1}' "$fx"; }
tree() { echo "$1"; local c; for c in $(children "$1"); do tree "$c"; done; }
{
    if [[ "$flags" == *-s* ]]; then
        d=$dev; while [ -n "$d" ]; do echo "$d"; d=$(field "$d" 3); done
    elif [ -z "$dev" ]; then
        awk -F'|' '$3==""{print $1}' "$fx"
    elif [[ "$flags" == *-d* ]]; then
        echo "$dev"
    else
        tree "$dev"
    fi
} | while read -r n; do
    out=""
    IFS=, read -ra cl <<< "$cols"
    for c in "${cl[@]}"; do
        case "$c" in
            NAME) v=$n; [[ "$flags" == *p* ]] || v=${n##*/} ;;
            TYPE) v=$(field "$n" 2) ;; MOUNTPOINT) v=$(field "$n" 4) ;;
            MODEL) v=$(field "$n" 5) ;; SERIAL) v=$(field "$n" 6) ;; PARTLABEL) v=$(field "$n" 7) ;;
            *) v= ;;
        esac
        out+="${out:+ }${v}"
    done
    echo "$out"
done
STUB
    printf '#!/bin/sh\necho /dev/sda1\n' > "${WORK}/bin/findmnt"
    printf '#!/bin/sh\necho 1000204886016\n' > "${WORK}/bin/blockdev"
    printf '#!/bin/sh\ncat "%s"\n' "${WORK}/pvs.txt" > "${WORK}/bin/pvs"
    chmod +x "${WORK}"/bin/{lsblk,findmnt,blockdev,pvs}
}

run_candidates() {
    env PATH="${WORK}/bin:$PATH" LSBLK_FIXTURE="${WORK}/disks.txt" \
        TS_SYS_BLOCK="${WORK}/hostfs/sys" TS_BYID_DIR="${WORK}/hostfs/byid" \
        bash <(ts_disk_candidates_script)
}

@test "a free whole disk is offered, with its stable name" {
    disks_fixture
    run run_candidates
    [ "$status" -eq 0 ]
    [[ "$output" == *"/dev/sdb|1000204886016|${WORK}/hostfs/byid/ata-MODB_SERB|MODB|SERB|disk"* ]]
}

@test "a free partition is offered, and its disk is not" {
    disks_fixture
    run run_candidates
    [[ "$output" == */dev/sdc1\|*\|partition* ]]
    [[ "$output" != */dev/sdc\|* ]]
}

@test "a mounted partition is not offered" {
    disks_fixture
    run run_candidates
    [[ "$output" != */dev/sdc2\|* ]]
}

@test "on the system disk only the partition labelled twinstor-data is offered" {
    disks_fixture
    run run_candidates
    [[ "$output" == */dev/sda2\|* ]]
    [[ "$output" != */dev/sda3\|* ]]
    [[ "$output" != */dev/sda1\|* ]]
    [[ "$output" != */dev/sda\|* ]]
}

@test "a disk with a RAID array on it, an LVM physical volume, or a read-only disk is not offered" {
    disks_fixture
    run run_candidates
    [[ "$output" != */dev/sdd\|* ]]
    [[ "$output" != */dev/sde\|* ]]
    [[ "$output" != */dev/sdf\|* ]]
}

@test "a partition that is an LVM physical volume is not offered" {
    disks_fixture
    run run_candidates
    [[ "$output" != */dev/sdg1\|* ]]
}

@test "a vendor-and-serial name is preferred over wwn and scsi-3 names, which are the fallback" {
    disks_fixture
    ln -s /dev/sdb "${WORK}/hostfs/byid/wwn-0x1111"
    run run_candidates
    # sdb has both: the vendor-and-serial one wins
    [[ "$output" == */dev/sdb\|*byid/ata-MODB_SERB\|* ]]
    # sda2 has only wwn- and scsi-3 links, so one of those is used rather than the kernel name
    [[ "$output" == */dev/sda2\|*byid/*\|* ]]
    [[ "$output" != */dev/sda2\|1000204886016\|/dev/sda2\|* ]]
}

@test "byid turns a typed kernel name into the stable one, or leaves it alone" {
    disks_fixture
    export TS_BYID_DIR="${WORK}/hostfs/byid"
    source <(ts_byid_fn)
    [ "$(byid /dev/sdb)" = "${WORK}/hostfs/byid/ata-MODB_SERB" ]
    [ "$(byid /dev/sdz)" = "/dev/sdz" ]
}
