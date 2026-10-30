#!/usr/bin/env bats
# The API template build downloaded and converted qcow2 images in
# DEPLOY_WORKDIR, which is under /tmp -- a RAM-backed tmpfs capped at half the
# memory on Debian 13. Ubuntu 26.04 failed "No space left on device" on a
# 6 GiB XO VM with a 35 GB disk. The image now goes under /var/tmp, and the
# free space there is checked before the download starts.
#
# Real curl (file:// URLs) and real sha512sum; only the XO upload, qemu-img
# and (where a shortage is simulated) df are stubbed.

setup() {
    load '../helpers/mock_helpers'
    load_script

    S=$(mktemp -d)
    CALLS="$S/calls.log"
    : > "$CALLS"
    unset XO_DEPLOY_IMAGE_SHA512

    mkdir -p "$S/origin" "$S/stage"
    head -c 300000 /dev/urandom > "$S/origin/image.raw"
    cp "$S/origin/image.raw" "$S/origin/image.qcow2"
    (cd "$S/origin" && sha512sum image.raw image.qcow2 > SHA512SUMS)
    RAW_URL="file://$S/origin/image.raw"
    QCOW_URL="file://$S/origin/image.qcow2"

    # Stand-in for /var/tmp, so the tests never write to the real one.
    TPL_API_STAGE_BASE="$S/stage"
    TPL_API_STAGE_DIR=""
    TPL_API_BASE_USED="https://xo.invalid"
    DEPLOY_SR_UUID="sr"
    DEPLOY_WORKDIR="$S/work"; mkdir -p "$DEPLOY_WORKDIR"

    xo_cookie_config() { :; }
    _vdi_resp() {
        local out=""
        while (( $# )); do
            [[ "$1" == "--output" ]] && out="$2"
            shift
        done
        printf '{"id":"0a1b2c3d-0000-4000-8000-000000000001"}' > "$out"
    }
    deploy_curl_stream_with_progress() {
        echo "stream" >> "$CALLS"
        [[ "$1" == "--digest" ]] && { printf -v "$3" '%s' "$FAKE_DIGEST"; shift 3; }
        printf -v "$3" '%s' "200"
        shift 3
        _vdi_resp "$@"
    }
    deploy_curl_upload_with_progress() {
        echo "upload $1" >> "$CALLS"
        printf -v "$3" '%s' "200"
        shift 3
        _vdi_resp "$@"
    }
    deploy_curl_with_progress() {
        echo "download $1" >> "$CALLS"
        local file="$1"; shift 2
        curl -s "$@"
    }
    qemu-img() {
        case "$1" in
            convert) echo "convert $6 $7" >> "$CALLS"; cp "$6" "$7" ;;
            *) : ;;
        esac
    }
}

teardown() {
    [[ -n "${S:-}" ]] && rm -rf "$S"
}

@test "API path: a qcow2 image is downloaded and converted under /var/tmp, not the /tmp workdir" {
    run tpl_api_import_image "Ubuntu test" "$QCOW_URL"
    [ "$status" -eq 0 ]
    # Every file the download, conversion and upload touched is in the
    # staging directory; nothing went to DEPLOY_WORKDIR.
    grep -q "^download $S/stage/xo-templates-" "$CALLS"
    grep -q "^convert $S/stage/xo-templates-[^ ]*/image.qcow2 $S/stage/xo-templates-[^ ]*/image.raw$" "$CALLS"
    grep -q "^upload $S/stage/xo-templates-[^ ]*/image.raw$" "$CALLS"
    run grep -c "$S/work" "$CALLS"
    [ "$output" = "0" ]
}

@test "API path: the staging directory is private and reused for the next image" {
    tpl_api_import_image "Ubuntu test" "$QCOW_URL" > /dev/null 2>&1
    local first="$TPL_API_STAGE_DIR"
    [ -d "$first" ]
    [ "$(stat -c %a "$first")" = "700" ]
    tpl_api_import_image "Ubuntu test 2" "$QCOW_URL" > /dev/null 2>&1
    [ "$TPL_API_STAGE_DIR" = "$first" ]
    [ "$(find "$S/stage" -mindepth 1 -maxdepth 1 | wc -l)" -eq 1 ]
}

@test "API path: too little free space stops the build before the download" {
    df() { printf 'Avail\n 100M\n'; }
    run tpl_api_import_image "Ubuntu test" "$QCOW_URL"
    [ "$status" -eq 1 ]
    [[ "$output" == *"not enough free space in $S/stage"* ]]
    [[ "$output" == *"100 MiB free, about 256 MiB needed"* ]]
    [[ "$output" == *"df -h $S/stage"* ]]
    [[ "$output" == *"TEMPLATE_BUILD_METHOD=ssh"* ]]
    # Nothing was downloaded, converted or uploaded.
    [ ! -s "$CALLS" ]
}

@test "API path: enough free space lets the build go ahead" {
    # Positive control for the shortage test: the same stub, with room.
    df() { printf 'Avail\n 100000M\n'; }
    run tpl_api_import_image "Ubuntu test" "$QCOW_URL"
    [ "$status" -eq 0 ]
    grep -q "^upload " "$CALLS"
}

@test "API path: a raw image streams and creates no staging directory" {
    FAKE_DIGEST=$(sha512sum "$S/origin/image.raw" | awk '{print $1}')
    run tpl_api_import_image "Debian test" "$RAW_URL"
    [ "$status" -eq 0 ]
    [ "$(cat "$CALLS")" = "stream" ]
    [ -z "$(ls -A "$S/stage")" ]
}

@test "tpl_cleanup removes the staging directory" {
    tpl_cleanup_failed_build_dispatch() { :; }
    TPL_API_STAGE_DIR="$S/stage/xo-templates-test"
    mkdir -p "$TPL_API_STAGE_DIR"
    head -c 1000 /dev/urandom > "$TPL_API_STAGE_DIR/image.raw"
    tpl_cleanup
    [ ! -e "$S/stage/xo-templates-test" ]
    [ -z "$TPL_API_STAGE_DIR" ]
    # And the /tmp workdir is still removed as before.
    [ ! -e "$S/work" ]
}
