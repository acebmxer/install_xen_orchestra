#!/usr/bin/env bats
# The API template build path verifies the image checksum. It used to
# download, convert and upload without checking anything, and both paths
# printed "image imported and checksum verified" even when nothing had been
# checked (the SSH streaming fallback, an origin with no sums entry).
#
# Real curl (file:// URLs) and real shaNsum throughout; only the XO upload
# and qemu-img are stubbed.

setup() {
    load '../helpers/mock_helpers'
    load_script

    S=$(mktemp -d)
    CALLS="$S/calls.log"
    : > "$CALLS"
    unset XO_DEPLOY_IMAGE_SHA512

    # An "origin": an image and its published SHA512SUMS (the default for an
    # unknown origin, which a file:// URL is).
    mkdir -p "$S/origin"
    head -c 300000 /dev/urandom > "$S/origin/image.raw"
    cp "$S/origin/image.raw" "$S/origin/image.qcow2"
    (cd "$S/origin" && sha512sum image.raw image.qcow2 > SHA512SUMS)
    RAW_URL="file://$S/origin/image.raw"
    QCOW_URL="file://$S/origin/image.qcow2"
    GOOD_RAW=$(sha512sum "$S/origin/image.raw" | awk '{print $1}')
}

teardown() {
    [[ -n "${S:-}" ]] && rm -rf "$S"
}

# --- deploy_verify_image_checksum, the modes the API path uses -------------

@test "local mode: a matching file is verified" {
    run deploy_verify_image_checksum "$RAW_URL" "$S/origin/image.raw" local
    [ "$status" -eq 0 ]
    [[ "$output" == *"image checksum verified"* ]]
    deploy_verify_image_checksum "$RAW_URL" "$S/origin/image.raw" local >/dev/null 2>&1
    [ "$DEPLOY_IMAGE_VERIFIED" = "true" ]
}

@test "local mode: a corrupted file is refused" {
    head -c 300000 /dev/urandom > "$S/bad.raw"
    run deploy_verify_image_checksum "$RAW_URL" "$S/bad.raw" local
    [ "$status" -eq 1 ]
    [[ "$output" == *"does not match its published checksum"* ]]
}

@test "local mode: no published sums file warns and is not reported as verified" {
    rm "$S/origin/SHA512SUMS"
    deploy_verify_image_checksum "$RAW_URL" "$S/origin/image.raw" local > "$S/out" 2>&1
    grep -q "cannot be verified" "$S/out"
    [ "$DEPLOY_IMAGE_VERIFIED" = "false" ]
}

@test "digest mode: the right digest passes, a wrong one is refused" {
    run deploy_verify_image_checksum "$RAW_URL" "$GOOD_RAW" digest
    [ "$status" -eq 0 ]
    [[ "$output" == *"image checksum verified"* ]]
    run deploy_verify_image_checksum "$RAW_URL" "$(printf '0%.0s' {1..128})" digest
    [ "$status" -eq 1 ]
}

@test "digest mode: an empty digest fails when XO_DEPLOY_IMAGE_SHA512 is pinned" {
    XO_DEPLOY_IMAGE_SHA512="$GOOD_RAW"
    run deploy_verify_image_checksum "$RAW_URL" "" digest
    [ "$status" -eq 1 ]
    [[ "$output" == *"Refusing to import it unverified"* ]]
}

@test "the digest width follows the origin, and a pin forces SHA-512" {
    [ "$(deploy_image_digest_bits 'https://cloud-images.ubuntu.com/noble/current/x.img')" = "256" ]
    XO_DEPLOY_IMAGE_SHA512=abc
    [ "$(deploy_image_digest_bits 'https://cloud-images.ubuntu.com/noble/current/x.img')" = "512" ]
}

# --- the stream helper hashes what passes through ------------------------

@test "the stream helper returns the digest of the bytes it sent" {
    # Called as tpl_api_import_image calls it, under `|| rc=$?`.
    local code="" digest="" rc=0
    deploy_curl_stream_with_progress --digest 512 digest \
        "$RAW_URL" "" code -s -T - "file://$S/received" 2>/dev/null || rc=$?
    [ "$rc" -eq 0 ]
    [ "$digest" = "$GOOD_RAW" ]
    cmp -s "$S/origin/image.raw" "$S/received"
}

@test "the stream helper still fails when the download fails" {
    local code="" digest="" rc=0
    deploy_curl_stream_with_progress --digest 512 digest \
        "file://$S/origin/missing.raw" "" code -s -T - "file://$S/received" 2>/dev/null || rc=$?
    [ "$rc" -ne 0 ]
}

@test "the stream helper works as before without --digest" {
    local code="" rc=0
    deploy_curl_stream_with_progress "$RAW_URL" "" code \
        -s -T - "file://$S/received" 2>/dev/null || rc=$?
    [ "$rc" -eq 0 ]
    cmp -s "$S/origin/image.raw" "$S/received"
}

# --- tpl_api_import_image ------------------------------------------------

# Stand-in for the XO upload: reads the body the real helper would send,
# answers 200 with a disk id, and reports a digest when asked for one.
_stub_xo_upload() {
    TPL_API_BASE_USED="https://xo.invalid"
    DEPLOY_SR_UUID="sr"
    DEPLOY_WORKDIR="$S/work"; mkdir -p "$DEPLOY_WORKDIR"
    xo_cookie_config() { :; }
    _vdi_resp() {
        local a out=""
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
        echo "upload" >> "$CALLS"
        printf -v "$3" '%s' "200"
        shift 3
        _vdi_resp "$@"
    }
    deploy_curl_with_progress() {
        # The real download, without the progress bar.
        local file="$1"; shift 2
        curl -s "$@"
    }
    qemu-img() {
        case "$1" in
            convert) echo "qemu-img convert" >> "$CALLS"; cp "$6" "$7" ;;
            *) : ;;
        esac
    }
}

@test "API path, raw image: a stream whose digest matches is verified" {
    _stub_xo_upload
    FAKE_DIGEST="$GOOD_RAW"
    run tpl_api_import_image "Debian test" "$RAW_URL"
    [ "$status" -eq 0 ]
    [[ "$output" == *"image imported and checksum verified"* ]]
}

@test "API path, raw image: a stream whose digest differs fails, leaving the disk id for cleanup" {
    _stub_xo_upload
    FAKE_DIGEST=$(printf '0%.0s' {1..128})
    tpl_api_import_image "Debian test" "$RAW_URL" > "$S/out" 2>&1 && false
    grep -q "does not match its published checksum" "$S/out"
    # tpl_api_cleanup_failed_build deletes the disk named here.
    [ "$TPL_ROOT_VDI" = "0a1b2c3d-0000-4000-8000-000000000001" ]
    run grep -c "image imported" "$S/out"
    [ "$output" = "0" ]
}

@test "API path, qcow2 image: verified before it is converted and uploaded" {
    _stub_xo_upload
    run tpl_api_import_image "Ubuntu test" "$QCOW_URL"
    [ "$status" -eq 0 ]
    [[ "$output" == *"image checksum verified"* ]]
    [[ "$output" == *"image imported and checksum verified"* ]]
    [ "$(cat "$CALLS")" = "$(printf 'qemu-img convert\nupload')" ]
}

@test "API path, qcow2 image: a corrupted download is never converted or uploaded" {
    _stub_xo_upload
    head -c 300000 /dev/urandom > "$S/origin/image.qcow2"
    run tpl_api_import_image "Ubuntu test" "$QCOW_URL"
    [ "$status" -eq 1 ]
    [[ "$output" == *"does not match its published checksum"* ]]
    [ ! -s "$CALLS" ]
}

# --- the success line only claims what was checked ------------------------

@test "the import line says 'not verified' when nothing was checked" {
    DEPLOY_IMAGE_VERIFIED=false
    run tpl_log_image_imported
    [[ "$output" == *"checksum not verified"* ]]
    DEPLOY_IMAGE_VERIFIED=true
    run tpl_log_image_imported
    [[ "$output" == *"image imported and checksum verified"* ]]
}

@test "the SSH import starts unverified, so the streaming fallback cannot inherit an earlier pass" {
    DEPLOY_IMAGE_VERIFIED=true
    deploy_import_vdi_staged() { return 0; }
    deploy_import_vdi_from_url "vdi" "$RAW_URL"
    [ "$DEPLOY_IMAGE_VERIFIED" = "false" ]
}
