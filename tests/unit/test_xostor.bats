#!/usr/bin/env bats
# Tests for the XOSTOR functions (xs_*) in install-xen-orchestra.sh.
#
# Nothing here reaches a real host: the pool is faked by replacing dom0_exec,
# dom0_xe and ts_exec, and every command the install would send is recorded.

setup() {
    load '../helpers/mock_helpers'
    load_script

    WORK="${BATS_TEST_TMPDIR}"
    DEPLOY_WORKDIR="${WORK}/work"
    mkdir -p "$DEPLOY_WORKDIR"
    NON_INTERACTIVE=false
    DRY_RUN=false
    SENT="${WORK}/sent"
    : > "$SENT"
}

fake_pool() {
    # Arguments: host count
    POOL_MASTER_IP=10.0.0.1
    HOST_USERNAME=root
    TS_MASTER_IDX=0
    TS_HOST_UUIDS=(u1 u2 u3 u4); TS_HOST_NAMES=(h1 h2 h3 h4)
    TS_HOST_IPS=(10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4)
    TS_HOST_UUIDS=("${TS_HOST_UUIDS[@]:0:$1}")
    TS_HOST_NAMES=("${TS_HOST_NAMES[@]:0:$1}")
    TS_HOST_IPS=("${TS_HOST_IPS[@]:0:$1}")
    FAKE_VERSION=8.3.0
    FAKE_VERSION_B=8.3.0
    FAKE_LINSTOR_SR=""
    FAKE_HAS_VG=""
    FAKE_MEM_KB=33554432
    dom0_xe() {
        case "$1" in
            *"uuid=u2 "*product_version*) echo "$FAKE_VERSION_B" ;;
            *product_version*) echo "$FAKE_VERSION" ;;
            "pbd-list currently-attached=false"*) echo "" ;;
        esac
    }
    dom0_exec() {
        echo "dom0: $*" >> "$SENT"
        case "$1" in
            "xe sr-list type=linstor"*) echo "$FAKE_LINSTOR_SR" ;;
            "xe sr-create"*) echo "sr-uuid-new" ;;
        esac
    }
    ts_exec() {
        echo "$1: $2" >> "$SENT"
        case "$2" in
            *"grep -qx linstor_group"*) [[ "$1" == "$FAKE_HAS_VG" ]] && return 0; return 1 ;;
            *MemTotal*) echo "$FAKE_MEM_KB" ;;
        esac
        return 0
    }
}

@test "XOSTOR is the last menu item and the sub-menu offers install" {
    [ "${MENU_NAMES[$((MENU_TOTAL - 1))]}" = "XOSTOR *" ]
    run grep -c '"install|Install XOSTOR' "${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
    [ "$output" -ge 1 ]
}

@test "xs_valid_name accepts plain names and rejects shell characters" {
    xs_valid_name "XOSTOR"
    xs_valid_name "Lab pool 1.a_b-c"
    ! xs_valid_name "x; reboot"
    ! xs_valid_name "a'b"
    ! xs_valid_name ""
}

@test "preflight passes on three matching hosts" {
    fake_pool 3
    run xs_preflight
    [ "$status" -eq 0 ]
    [[ "$output" == *"Pool checks passed"* ]]
}

@test "preflight refuses a pool of two" {
    fake_pool 2
    run xs_preflight
    [ "$status" -eq 1 ]
    [[ "$output" == *"at least 3"* ]]
}

@test "preflight refuses hosts on different XCP-ng versions" {
    fake_pool 3
    FAKE_VERSION_B=8.2.1
    run xs_preflight
    [ "$status" -eq 1 ]
    [[ "$output" == *"different XCP-ng versions"* ]]
}

@test "preflight refuses a pool that already has a XOSTOR SR" {
    fake_pool 3
    FAKE_LINSTOR_SR=abc-123
    run xs_preflight
    [ "$status" -eq 1 ]
    [[ "$output" == *"already has a XOSTOR"* ]]
}

@test "preflight refuses a host that already has linstor_group, and does not touch it" {
    fake_pool 3
    FAKE_HAS_VG=10.0.0.3
    run xs_preflight
    [ "$status" -eq 1 ]
    [[ "$output" == *"already has a volume group named linstor_group"* ]]
    ! grep -q "vgremove" "$SENT"
}

@test "install: workers get packages first, the master last, then LVM, then one SR" {
    fake_pool 3
    XS_DISKS=("/dev/disk/by-id/a" "/dev/disk/by-id/b" "/dev/disk/by-id/c")
    XS_PROVISIONING=thin XS_REPLICATION=2 XS_SR_NAME=lab
    sleep() { :; }
    xs_wait_xapi() { return 0; }
    run xs_do_install
    [ "$status" -eq 0 ]
    mapfile -t yum < <(grep -n "yum install" "$SENT" | cut -d: -f2)
    [[ "${yum[0]}" == 10.0.0.2* ]]
    [[ "${yum[1]}" == 10.0.0.3* ]]
    [[ "${yum[2]}" == 10.0.0.1* ]]
    grep -q "vgcreate linstor_group /dev/disk/by-id/a" "$SENT"
    grep -q "lvcreate -l 100%FREE -T linstor_group/thin_device" "$SENT"
    [ "$(grep -c 'xe sr-create' "$SENT")" -eq 1 ]
    grep -q "device-config:group-name=linstor_group/thin_device device-config:redundancy=2 device-config:provisioning=thin" "$SENT"
}

@test "install: thick provisioning makes no thin pool and names the plain group" {
    fake_pool 3
    XS_DISKS=("/dev/x" "" "/dev/y")
    XS_PROVISIONING=thick XS_REPLICATION=1 XS_SR_NAME=lab
    xs_wait_xapi() { return 0; }
    run xs_do_install
    [ "$status" -eq 0 ]
    ! grep -q "lvcreate" "$SENT"
    ! grep -q "10.0.0.2: pvcreate" "$SENT"
    grep -q "device-config:group-name=linstor_group device-config:redundancy=1 device-config:provisioning=thick" "$SENT"
}

@test "install: a failed sr-create removes the volume groups it made" {
    fake_pool 3
    XS_DISKS=("/dev/x" "/dev/y" "/dev/z")
    XS_PROVISIONING=thick XS_REPLICATION=3 XS_SR_NAME=lab
    xs_wait_xapi() { return 0; }
    dom0_exec() { echo "dom0: $*" >> "$SENT"; case "$1" in "xe sr-create"*) return 1 ;; esac; }
    run xs_do_install
    [ "$status" -eq 1 ]
    [ "$(grep -c 'vgremove -f linstor_group' "$SENT")" -eq 3 ]
}

@test "install: a failed package install stops before any disk is touched" {
    fake_pool 3
    XS_DISKS=("/dev/x" "/dev/y" "/dev/z")
    XS_PROVISIONING=thick XS_REPLICATION=3 XS_SR_NAME=lab
    ts_exec() { echo "$1: $2" >> "$SENT"; [[ "$2" == *"yum install"* ]] && return 1; return 0; }
    run xs_do_install
    [ "$status" -eq 1 ]
    ! grep -q "pvcreate" "$SENT"
}
