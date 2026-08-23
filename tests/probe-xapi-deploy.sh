#!/bin/bash
# Probe the XAPI assumptions behind install-xen-orchestra.sh --deploy.
#
# --deploy drives `xe` on a pool master to create a VM and stream a cloud image
# into its disk. None of that can be exercised by the BATS suite, which has no
# hypervisor to talk to, so this script checks the assumptions directly against
# a real host before you trust the deploy path.
#
# The disk-transfer probes are the point of this script. There are several ways
# to get bytes into a VDI and they do not all work on every release, so each
# candidate is tried and round-tripped through `vdi-export` with a checksum —
# an exit code of 0 does not prove the bytes actually landed.
#
# It is deliberately conservative:
#   - Everything it creates is named "xo-probe-<run id>" and destroyed again on
#     exit, including on failure or Ctrl-C.
#   - It never modifies, starts, or deletes anything it did not create.
#   - The VM it creates is never started.
#   - Total footprint is ~100 MiB of scratch VDI for a few seconds.
#
# Usage:
#   ./tests/probe-xapi-deploy.sh --host 192.168.1.10 [--user root] [--sr <uuid>]
#   ./tests/probe-xapi-deploy.sh --host pool.lan --key ~/.ssh/id_ed25519
#
# Run it from your workstation, exactly as you would run --deploy.

set -uo pipefail

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; NC=$'\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILED_PROBES=()
WORKING_TRANSPORTS=()

info()  { echo "${BLUE}[INFO]${NC} $*"; }
warn()  { echo "${YELLOW}[WARN]${NC} $*"; }
die()   { echo "${RED}[FATAL]${NC} $*" >&2; exit 1; }

probe_start() { echo ""; echo "${BOLD}── $* ${NC}"; }

pass() { echo "  ${GREEN}PASS${NC}  $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
skip() { echo "  ${YELLOW}SKIP${NC}  $*"; SKIP_COUNT=$((SKIP_COUNT + 1)); }
fail() {
    echo "  ${RED}FAIL${NC}  $*"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILED_PROBES+=("$*")
}
detail() { echo "        ${*}"; }

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

POOL_HOST=""
POOL_USER="root"
POOL_PASS=""
POOL_KEY=""
SR_UUID=""
KEEP=false
PAYLOAD_MB=4
IMAGE_URL="${XO_DEPLOY_IMAGE_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.raw}"

usage() {
    cat <<'EOF'
Probe the XAPI assumptions behind --deploy against a real pool master.

Options:
  --host ADDR       Pool master address (required)
  --user NAME       SSH username (default: root)
  --key PATH        SSH private key; if omitted, you are prompted for a password
  --sr UUID         Storage repository to use for scratch VDIs
                    (default: the first user SR found)
  --image URL       Cloud image URL to reachability-test (default: Debian 13)
  --payload-mb N    Size of the test payload per transport (default: 4).
                    Raise it to expose transports that buffer in memory —
                    a 4 MiB payload hides that, a 1024 MiB one does not.
  --keep            Leave created objects behind for inspection
  --help            Show this message

Everything created is named xo-probe-<run id> and removed on exit.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)  POOL_HOST="${2:-}"; shift 2 ;;
        --user)  POOL_USER="${2:-}"; shift 2 ;;
        --key)   POOL_KEY="${2:-}";  shift 2 ;;
        --sr)    SR_UUID="${2:-}";   shift 2 ;;
        --image) IMAGE_URL="${2:-}"; shift 2 ;;
        --payload-mb) PAYLOAD_MB="${2:-}"; shift 2 ;;
        --keep)  KEEP=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[[ -n "$POOL_HOST" ]] || { usage; die "--host is required"; }

RUN_ID="$(date +%s)-$$"
PROBE_TAG="xo-probe-${RUN_ID}"
WORKDIR=$(mktemp -d --tmpdir xo-probe-XXXXXX)
SSH_CTL="${WORKDIR}/ssh-ctl"

# Size of the test payload pushed through each candidate transport.
PAYLOAD_BYTES=$((PAYLOAD_MB * 1048576))

# Scratch VDIs must be able to hold the payload with room to spare.
SCRATCH_VDI_MB=$((PAYLOAD_MB * 2 + 8))

# ---------------------------------------------------------------------------
# Transport — mirrors deploy's dom0_exec so we test the real path
# ---------------------------------------------------------------------------

# Three auth modes, in order of preference:
#
#   key       --key was given.
#   sshpass   No key, but sshpass is installed. We collect the password once
#             and hand it to ssh via the environment.
#   prompt    No key and no sshpass. Plain ssh handles the password itself.
#             Connection multiplexing means it only asks once — the master
#             connection authenticates, and every later call rides that socket.
#
# sshpass is deliberately not required: --deploy installs it when missing, but
# a diagnostic you run *before* trusting the deploy path should not make you
# install something first.
AUTH_MODE="prompt"
if [[ -n "$POOL_KEY" ]]; then
    AUTH_MODE="key"
elif command -v sshpass >/dev/null 2>&1; then
    AUTH_MODE="sshpass"
    read -rsp "Password for ${POOL_USER}@${POOL_HOST}: " POOL_PASS
    echo ""
    [[ -n "$POOL_PASS" ]] || die "password is required"
fi

SSH_COMMON=(
    -o ControlMaster=auto
    -o ControlPath="$SSH_CTL"
    -o ControlPersist=300
    -o StrictHostKeyChecking=accept-new
    -o ConnectTimeout=15
)

dom0() {
    case "$AUTH_MODE" in
        key)
            ssh -i "$POOL_KEY" -o IdentitiesOnly=yes "${SSH_COMMON[@]}" \
                "${POOL_USER}@${POOL_HOST}" "$@"
            ;;
        sshpass)
            SSHPASS="$POOL_PASS" sshpass -e ssh "${SSH_COMMON[@]}" \
                "${POOL_USER}@${POOL_HOST}" "$@"
            ;;
        *)
            ssh "${SSH_COMMON[@]}" "${POOL_USER}@${POOL_HOST}" "$@"
            ;;
    esac
}

xe_() { dom0 "xe $*" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

# ---------------------------------------------------------------------------
# Cleanup — every created UUID is registered here and torn down on exit
# ---------------------------------------------------------------------------

CREATED_VMS=()
CREATED_VDIS=()
XAPI_SESSION=""

cleanup() {
    local rc=$?
    echo ""
    if [[ "$KEEP" == "true" ]]; then
        warn "--keep given; leaving created objects in place:"
        [[ ${#CREATED_VMS[@]}  -gt 0 ]] && warn "  VMs:  ${CREATED_VMS[*]}"
        [[ ${#CREATED_VDIS[@]} -gt 0 ]] && warn "  VDIs: ${CREATED_VDIS[*]}"
    else
        if [[ ${#CREATED_VMS[@]} -gt 0 || ${#CREATED_VDIS[@]} -gt 0 ]]; then
            info "Cleaning up probe objects..."
        fi
        local u
        for u in "${CREATED_VMS[@]:-}"; do
            [[ -n "$u" ]] && xe_ "vm-uninstall uuid=${u} force=true" >/dev/null 2>&1
        done
        for u in "${CREATED_VDIS[@]:-}"; do
            [[ -n "$u" ]] && xe_ "vdi-destroy uuid=${u}" >/dev/null 2>&1
        done
        dom0 "rm -f /tmp/${PROBE_TAG}-*" >/dev/null 2>&1
    fi

    if [[ -n "$XAPI_SESSION" ]]; then
        curl -sk --max-time 10 -H 'Content-Type: text/xml' --data-binary \
            "<?xml version=\"1.0\"?><methodCall><methodName>session.logout</methodName><params><param><value><string>${XAPI_SESSION}</string></value></param></params></methodCall>" \
            "https://${POOL_HOST}/" >/dev/null 2>&1
    fi

    if [[ -S "$SSH_CTL" ]]; then
        ssh -o ControlPath="$SSH_CTL" -O exit "${POOL_USER}@${POOL_HOST}" 2>/dev/null
    fi
    rm -rf "$WORKDIR"
    exit $rc
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Scratch VDI helpers used by the transport probes
# ---------------------------------------------------------------------------

# Create a throwaway 16MiB VDI and record it for cleanup.
#
# The result comes back in $SCRATCH_VDI rather than on stdout deliberately:
# calling this as $(make_scratch_vdi ...) would run it in a subshell, and the
# CREATED_VDIS append would be discarded along with it — leaving scratch disks
# stranded on the pool.
SCRATCH_VDI=""
make_scratch_vdi() {
    local label="$1"
    SCRATCH_VDI=$(xe_ "vdi-create sr-uuid=${SR_UUID} name-label='${PROBE_TAG}-${label}' virtual-size=${SCRATCH_VDI_MB}MiB type=user" 2>/dev/null)
    if [[ -z "$SCRATCH_VDI" || "$SCRATCH_VDI" == *"rror"* ]]; then
        SCRATCH_VDI=""
        return 1
    fi
    CREATED_VDIS+=("$SCRATCH_VDI")
    return 0
}

# Export a VDI and compare the leading PAYLOAD_BYTES against the known digest.
# Returns 0 on match, 1 on mismatch, 2 when the export itself failed.
verify_vdi() {
    local vdi="$1" expect="$2"
    local out="/tmp/${PROBE_TAG}-verify.bin"

    dom0 "xe vdi-export uuid=${vdi} filename=${out} format=raw" >/dev/null 2>&1 || return 2

    local got
    got=$(dom0 "head -c ${PAYLOAD_BYTES} ${out} | md5sum | cut -d' ' -f1; rm -f ${out}" | tr -d '\r')
    [[ "$got" == "$expect" ]]
}

# Run one candidate transport end to end and report the verdict.
# Arguments: label, description, the shell command to perform the transfer
#            (with %VDI% substituted for the scratch VDI's UUID)
try_transport() {
    local label="$1" desc="$2" cmd="$3" is_local="${4:-remote}"
    local vdi

    make_scratch_vdi "$label" || { fail "${desc}: could not create a scratch VDI"; return 1; }
    vdi="$SCRATCH_VDI"

    local run_cmd="${cmd//%VDI%/$vdi}"
    local err

    if [[ "$is_local" == "local" ]]; then
        err=$(eval "$run_cmd" 2>&1 >/dev/null)
    else
        err=$(dom0 "$run_cmd" 2>&1 >/dev/null)
    fi
    local rc=$?

    if [[ $rc -ne 0 ]]; then
        fail "${desc}"
        [[ -n "$err" ]] && detail "error: $(head -3 <<< "$err" | tr '\n' ' ')"
        return 1
    fi

    verify_vdi "$vdi" "$PAYLOAD_MD5"
    case $? in
        0)
            pass "${desc}"
            WORKING_TRANSPORTS+=("$desc")
            return 0
            ;;
        1)
            fail "${desc}: transfer reported success but the data does not match"
            detail "this is the dangerous case — it would produce a VM that will not boot"
            return 1
            ;;
        *)
            skip "${desc}: transfer succeeded but vdi-export failed, cannot verify"
            return 0
            ;;
    esac
}

# ---------------------------------------------------------------------------

echo ""
echo "${BOLD}XAPI deploy probe${NC}"
echo "Target: ${POOL_USER}@${POOL_HOST}   Run id: ${RUN_ID}"

# --- Probe 1: connectivity and xe -----------------------------------------

probe_start "1. Connectivity and xe availability"

# Open the master connection with the terminal still attached: in prompt mode
# this is where ssh asks for the password, and redirecting it here would hide
# the prompt behind an apparent hang.
if [[ "$AUTH_MODE" == "prompt" ]]; then
    info "Authenticating (you will be asked once; later calls reuse the connection)"
fi
if ! dom0 "true"; then
    die "cannot SSH to ${POOL_USER}@${POOL_HOST}"
fi
pass "SSH connection established"

if ! dom0 "command -v xe" >/dev/null 2>&1; then
    die "'xe' not found — this is not a XenServer/XCP-ng host"
fi
pass "xe is present"

HOST_NAME=$(xe_ "host-list params=name-label --minimal" 2>/dev/null | cut -d, -f1)
HOST_VER=$(dom0 "cat /etc/xcp-ng-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null" | tr -d '\r')
pass "Host: ${HOST_NAME:-unknown} — ${HOST_VER:-version unknown}"

DOM0_FREE=$(dom0 "df -BM --output=avail /var/tmp 2>/dev/null | tail -1 | tr -d ' M'" | tr -d '\r')
if [[ -n "$DOM0_FREE" ]]; then
    if (( DOM0_FREE > 4096 )); then
        pass "dom0 has ${DOM0_FREE} MiB free in /var/tmp (enough to stage a 3 GiB image)"
    else
        warn "dom0 has only ${DOM0_FREE} MiB free in /var/tmp"
        detail "a transport that stages the image on disk would not fit"
    fi
fi

# --- Probe 2: SR and network enumeration ----------------------------------

probe_start "2. SR and network enumeration"

SR_LIST=$(dom0 'for u in $(xe sr-list content-type=user params=uuid --minimal | tr "," " "); do
        name=$(xe sr-param-get uuid=$u param-name=name-label 2>/dev/null)
        size=$(xe sr-param-get uuid=$u param-name=physical-size 2>/dev/null)
        used=$(xe sr-param-get uuid=$u param-name=physical-utilisation 2>/dev/null)
        free=$(( (size - used) / 1073741824 ))
        echo "$u|$name (${free} GiB free)"
    done' 2>/dev/null | tr -d '\r' | grep -v '^$')

if [[ -z "$SR_LIST" ]]; then
    fail "No user SRs found — deploy would have nowhere to put the VM"
else
    pass "Found $(echo "$SR_LIST" | wc -l) usable SR(s):"
    while IFS= read -r line; do echo "          ${line#*|}"; done <<< "$SR_LIST"
fi

NET_LIST=$(dom0 'for u in $(xe network-list params=uuid --minimal | tr "," " "); do
        name=$(xe network-param-get uuid=$u param-name=name-label 2>/dev/null)
        echo "$u|$name"
    done' 2>/dev/null | tr -d '\r' | grep -v '^$')

if [[ -z "$NET_LIST" ]]; then
    fail "No networks found"
else
    pass "Found $(echo "$NET_LIST" | wc -l) network(s)"
fi

if [[ -z "$SR_UUID" && -n "$SR_LIST" ]]; then
    SR_UUID=$(head -1 <<< "$SR_LIST" | cut -d'|' -f1)
    info "Using SR ${SR_UUID} for scratch VDIs"
fi
[[ -n "$SR_UUID" ]] || die "no SR available; pass --sr UUID"

# --- Probe 3: dom0 outbound internet --------------------------------------

probe_start "3. Pool master outbound internet"

IMG_HEAD=$(dom0 "curl -fsSLI '${IMAGE_URL}' 2>/dev/null | tr -d '\r'")
if [[ -z "$IMG_HEAD" ]]; then
    fail "Pool master cannot reach ${IMAGE_URL}"
    detail "deploy streams the cloud image from the host, so this must work"
else
    IMG_LEN=$(grep -i '^content-length:' <<< "$IMG_HEAD" | tail -1 | awk '{print $2}')
    if [[ -n "$IMG_LEN" ]]; then
        pass "Image reachable ($(( IMG_LEN / 1048576 )) MiB)"
    else
        pass "Image reachable (size not reported)"
    fi
fi

# --- Probe 4: XAPI session ------------------------------------------------
# Needed by the HTTP transports below. Sessions are pool-wide, so the same
# reference works whether the request comes from here or from dom0 itself.

probe_start "4. XAPI HTTPS session"

if [[ -z "$POOL_PASS" ]]; then
    echo "  The HTTP transports need the ${POOL_USER} password to log in to XAPI."
    read -rsp "  Password (blank to skip those probes): " POOL_PASS
    echo ""
fi

if [[ -z "$POOL_PASS" ]]; then
    skip "no password supplied; HTTP transports will be skipped"
else
    LOGIN_XML="<?xml version=\"1.0\"?><methodCall><methodName>session.login_with_password</methodName><params><param><value><string>${POOL_USER}</string></value></param><param><value><string>${POOL_PASS}</string></value></param></params></methodCall>"
    XAPI_SESSION=$(curl -sk --max-time 20 -H 'Content-Type: text/xml' \
        --data-binary "$LOGIN_XML" "https://${POOL_HOST}/" 2>/dev/null \
        | grep -o 'OpaqueRef:[a-f0-9-]*' | head -1)

    if [[ -z "$XAPI_SESSION" ]]; then
        fail "Could not obtain an XAPI session over HTTPS"
    else
        pass "Session acquired (${XAPI_SESSION:0:20}...)"
    fi
fi

# --- Probe 5: candidate disk transports -----------------------------------
# Every way of getting bytes into a VDI, each round-tripped and checksummed.
# The winner decides how deploy imports the cloud image.

probe_start "5. Disk transports  ${BOLD}(these decide the deploy architecture)${NC}"

LOCAL_PAYLOAD="${WORKDIR}/payload.bin"
REMOTE_PAYLOAD="/tmp/${PROBE_TAG}-payload.bin"

dd if=/dev/urandom of="$LOCAL_PAYLOAD" bs=1M count="$PAYLOAD_MB" 2>/dev/null
PAYLOAD_MD5=$(md5sum "$LOCAL_PAYLOAD" | cut -d' ' -f1)

# Push the same payload to dom0. This also proves SSH stdin streaming works at
# all, independently of xe — so if the xe-over-stdin transport fails we know
# the transport is the problem, not the pipe.
if dom0 "cat > ${REMOTE_PAYLOAD}" < "$LOCAL_PAYLOAD"; then
    REMOTE_MD5=$(dom0 "md5sum ${REMOTE_PAYLOAD} | cut -d' ' -f1" | tr -d '\r')
    if [[ "$REMOTE_MD5" == "$PAYLOAD_MD5" ]]; then
        pass "SSH stdin streaming works (payload staged on dom0 intact)"
    else
        fail "SSH stdin streaming corrupted the payload"
    fi
else
    fail "Could not stage the payload on dom0 over SSH"
fi

echo ""
detail "${BOLD}A. xe vdi-import, piped on dom0${NC}  (what deploy uses today)"
try_transport "a" "A: cat file | xe vdi-import filename=/dev/stdin" \
    "cat ${REMOTE_PAYLOAD} | xe vdi-import uuid=%VDI% filename=/dev/stdin format=raw"

echo ""
detail "${BOLD}B. xe vdi-import, fed over SSH stdin${NC}  (the config-drive path)"
make_scratch_vdi "b"
VDI_B="$SCRATCH_VDI"
if [[ -z "$VDI_B" ]]; then
    fail "B: could not create a scratch VDI"
else
    ERR_B=$(dom0 "xe vdi-import uuid=${VDI_B} filename=/dev/stdin format=raw" < "$LOCAL_PAYLOAD" 2>&1 >/dev/null)
    if [[ $? -ne 0 ]]; then
        fail "B: xe vdi-import over SSH stdin"
        [[ -n "$ERR_B" ]] && detail "error: $(head -3 <<< "$ERR_B" | tr '\n' ' ')"
    else
        verify_vdi "$VDI_B" "$PAYLOAD_MD5" \
            && { pass "B: xe vdi-import over SSH stdin"; WORKING_TRANSPORTS+=("B: xe vdi-import over SSH stdin"); } \
            || fail "B: transfer succeeded but the data does not match"
    fi
fi

echo ""
detail "${BOLD}C. xe vdi-import from a file on dom0${NC}  (needs disk space, no pipe)"
try_transport "c" "C: xe vdi-import filename=<file on dom0>" \
    "xe vdi-import uuid=%VDI% filename=${REMOTE_PAYLOAD} format=raw"

if [[ -n "$XAPI_SESSION" ]]; then
    echo ""
    detail "${BOLD}D. HTTPS PUT from this workstation${NC}  (known length)"
    try_transport "d" "D: PUT /import_raw_vdi from workstation" \
        "curl -sk -f --max-time 300 -T '${LOCAL_PAYLOAD}' 'https://${POOL_HOST}/import_raw_vdi?session_id=${XAPI_SESSION}&vdi=%VDI%&format=raw'" \
        "local"

    echo ""
    detail "${BOLD}E. HTTPS PUT from dom0 to itself${NC}  (known length)"
    try_transport "e" "E: PUT /import_raw_vdi from dom0, file" \
        "curl -sk -f --max-time 300 -T ${REMOTE_PAYLOAD} 'https://localhost/import_raw_vdi?session_id=${XAPI_SESSION}&vdi=%VDI%&format=raw'"

    echo ""
    detail "${BOLD}F. HTTPS PUT from dom0, piped${NC}  ${BOLD}(the one that matters)${NC}"
    detail "   this is curl <image url> | curl -T - — zero disk, zero workstation traffic"
    try_transport "f" "F: PUT /import_raw_vdi from dom0, chunked pipe" \
        "cat ${REMOTE_PAYLOAD} | curl -sk -f --max-time 300 -T - 'https://localhost/import_raw_vdi?session_id=${XAPI_SESSION}&vdi=%VDI%&format=raw'"

    echo ""
    detail "${BOLD}G. HTTPS PUT from dom0, piped with --data-binary${NC}"
    detail "   ${YELLOW}warning:${NC} --data-binary @- buffers the whole body in memory before"
    detail "   sending. Fine for this payload, but a 3 GiB image would try to"
    detail "   allocate 3 GiB of dom0 RAM. Passing here does not make it safe."
    try_transport "g" "G: PUT /import_raw_vdi from dom0, piped + Content-Length (buffers in RAM)" \
        "cat ${REMOTE_PAYLOAD} | curl -sk -f --max-time 300 -X PUT --data-binary @- -H 'Content-Type: application/octet-stream' -H 'Content-Length: ${PAYLOAD_BYTES}' 'https://localhost/import_raw_vdi?session_id=${XAPI_SESSION}&vdi=%VDI%&format=raw'"

    echo ""
    detail "${BOLD}H. HTTPS PUT from dom0, true streaming${NC}  ${BOLD}(the ideal)${NC}"
    detail "   -T - streams stdin without buffering; suppressing curl's chunked"
    detail "   header and supplying the length by hand is what XAPI needs. If"
    detail "   this works, deploy needs no temp file and no dom0 disk space."
    try_transport "h" "H: PUT /import_raw_vdi from dom0, streamed + forced Content-Length" \
        "cat ${REMOTE_PAYLOAD} | curl -sk -f --max-time 300 -T - -H 'Transfer-Encoding:' -H 'Content-Length: ${PAYLOAD_BYTES}' 'https://localhost/import_raw_vdi?session_id=${XAPI_SESSION}&vdi=%VDI%&format=raw'"
else
    skip "D–G: HTTP transports need an XAPI session"
fi

# --- Probe 6: template and VM creation ------------------------------------

probe_start "6. 'Other install media' template and VM creation"

TEMPLATE=$(xe_ "template-list name-label='Other install media' params=uuid --minimal" 2>/dev/null)
if [[ -z "$TEMPLATE" ]]; then
    fail "'Other install media' template not found"
else
    pass "Template found: ${TEMPLATE}"

    VM=$(xe_ "vm-install template=${TEMPLATE} new-name-label='${PROBE_TAG}-vm' sr-uuid=${SR_UUID}" 2>/dev/null)
    if [[ -z "$VM" || "$VM" == *"rror"* ]]; then
        fail "vm-install failed: ${VM:-no output}"
    else
        CREATED_VMS+=("$VM")
        pass "VM created: ${VM}"

        VBDS=$(xe_ "vbd-list vm-uuid=${VM} type=Disk params=uuid --minimal" 2>/dev/null)
        if [[ -z "$VBDS" ]]; then
            pass "Template provisions no disks (deploy attaches its own at device 0)"
        else
            VBD_COUNT=$(tr ',' '\n' <<< "$VBDS" | grep -c .)
            pass "Template provisioned ${VBD_COUNT} disk(s) — deploy removes them first"
        fi

        if xe_ "vm-param-set uuid=${VM} VCPUs-max=2" >/dev/null 2>&1 \
           && xe_ "vm-param-set uuid=${VM} VCPUs-at-startup=2" >/dev/null 2>&1; then
            pass "vCPU parameters accepted"
        else
            fail "Setting VCPUs-max / VCPUs-at-startup failed"
        fi

        if xe_ "vm-memory-limits-set uuid=${VM} static-min=4GiB dynamic-min=4GiB dynamic-max=4GiB static-max=4GiB" >/dev/null 2>&1; then
            pass "vm-memory-limits-set accepted GiB units"
        else
            fail "vm-memory-limits-set failed"
        fi

        if xe_ "vm-param-set uuid=${VM} HVM-boot-policy='BIOS order'" >/dev/null 2>&1 \
           && xe_ "vm-param-set uuid=${VM} HVM-boot-params:order=c" >/dev/null 2>&1; then
            BOOT_POLICY=$(xe_ "vm-param-get uuid=${VM} param-name=HVM-boot-policy" 2>/dev/null)
            pass "Boot policy set to '${BOOT_POLICY}' with disk-only order"
        else
            fail "Setting HVM-boot-policy / boot order failed"
        fi

        make_scratch_vdi "vbd"
        SCRATCH_VBD="$SCRATCH_VDI"
        if [[ -n "$SCRATCH_VBD" ]]; then
            if xe_ "vbd-create vm-uuid=${VM} vdi-uuid=${SCRATCH_VBD} device=0 bootable=true type=Disk mode=RW" >/dev/null 2>&1; then
                pass "vbd-create attached a VDI at device 0"
            else
                fail "vbd-create at device 0 failed"
            fi
        fi

        if [[ -n "$NET_LIST" ]]; then
            NET_UUID=$(head -1 <<< "$NET_LIST" | cut -d'|' -f1)
            if xe_ "vif-create vm-uuid=${VM} network-uuid=${NET_UUID} device=0" >/dev/null 2>&1; then
                pass "vif-create attached an interface at device 0"
            else
                fail "vif-create failed"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

echo ""
echo "${BOLD}═══════════════════════════════════════════════════${NC}"
echo "${BOLD}Result${NC}: ${GREEN}${PASS_COUNT} passed${NC}, ${RED}${FAIL_COUNT} failed${NC}, ${YELLOW}${SKIP_COUNT} skipped${NC}"
echo "${BOLD}═══════════════════════════════════════════════════${NC}"

echo ""
if [[ ${#WORKING_TRANSPORTS[@]} -eq 0 ]]; then
    echo "${RED}No disk transport worked.${NC} deploy cannot import an image on this host."
else
    echo "${BOLD}Working disk transports:${NC}"
    for t in "${WORKING_TRANSPORTS[@]}"; do echo "  ${GREEN}✓${NC} $t"; done
    echo ""
    echo "${BOLD}Preference order for deploy:${NC}  H > E > C > A > G > D"
    echo ""
    echo "  H  streams on the host: no temp file, no memory blowup, no"
    echo "     workstation traffic. Use it if it passed."
    echo "  E  stages a temp file on dom0 first. Safe at any size, but needs"
    echo "     free space on dom0 equal to the image (3 GiB for Debian 13)."
    echo "  C  same staging, via xe instead of HTTP."
    echo "  G  ${YELLOW}avoid at image scale${NC} — --data-binary buffers the entire body in"
    echo "     RAM, so a 3 GiB image needs 3 GiB of dom0 memory. Passing at a"
    echo "     small payload size proves nothing about a real image."
    echo "  D  last resort: pulls the image to your workstation and pushes it"
    echo "     back, doubling transfer over your slowest link."
    if [[ "$PAYLOAD_MB" -lt 512 ]]; then
        echo ""
        warn "Payload was only ${PAYLOAD_MB} MiB. Re-run the winner at a realistic size"
        warn "before trusting it:  --payload-mb 1024"
    fi
fi

if [[ $FAIL_COUNT -gt 0 ]]; then
    echo ""
    echo "${RED}Failures:${NC}"
    for f in "${FAILED_PROBES[@]}"; do echo "  - $f"; done
fi
echo ""

[[ ${#WORKING_TRANSPORTS[@]} -gt 0 ]]
