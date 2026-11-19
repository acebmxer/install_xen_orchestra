#!/usr/bin/env bash
# Runs the script's real update_xo or rebuild_xo against a throwaway install
# directory, with the parts that touch the system or the network replaced,
# and with one stage made to fail. Used by tests/unit/test_failed_downtime_report.bats
# and the integration smoke test, so the same scenario runs on every distro in
# the CI matrix.
#
# Usage: downtime_scenario.sh update|rebuild STAGE
#        downtime_scenario.sh restore BACKUP_NAME   (--restore --backup-file BACKUP_NAME --non-interactive)
#   STAGE: none     nothing fails (a successful run)
#          flush    the token flush, after the service stopped, before the backup
#          backup   the backup copy itself
#          pull     the git fetch in --update, after the backup
#          clone    the git clone in --rebuild, after the backup
#          clonestart  the clone fails and so does the restart that follows it
#          build    the build, after the install was changed
#          start    systemctl start, the last step
# Environment: XO_TEST_ROOT, a directory the scenario may fill. Everything it
# makes lives under there: install/ (the fake install), backups/, and
# systemctl.log (one line per systemctl call).
# The exit status is the script's own.

set -euo pipefail

OPERATION="${1:?update, rebuild or restore}"
STAGE="${2:?stage or backup name}"
ROOT="${XO_TEST_ROOT:?XO_TEST_ROOT}"
SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/install-xen-orchestra.sh"

_XO_SOURCE_ONLY=1 source "$SCRIPT"

# The script's own top-level ERR trap stays: it is part of what runs for real.
INSTALL_DIR="${ROOT}/install"
BACKUP_DIR="${ROOT}/backups"
BACKUP_KEEP=5
GIT_BRANCH=master
SERVICE_USER="$(id -un)"
SSL_CERT_DIR="${ROOT}/ssl"
mkdir -p "$INSTALL_DIR" "$BACKUP_DIR"
echo "xo" > "${INSTALL_DIR}/marker"
echo "{}" > "${INSTALL_DIR}/package.json"

# Privileged commands run as this user, on the throwaway directories. Only
# git is faked: a clone must not reach the network.
sudo() {
    if [[ "${1:-}" == "git" && "${2:-}" == "clone" ]]; then
        [[ "$STAGE" == "clone" || "$STAGE" == "clonestart" ]] && return 1
        mkdir -p "${*: -1}"
        return 0
    fi
    # Ownership and permission changes target system paths (/etc/xo-server,
    # /var/lib/xo-server) the test machine does not have.
    case "${1:-}" in
        chown | chmod | gpasswd) return 0 ;;
    esac
    "$@"
}
systemctl() {
    echo "systemctl $*" >> "${ROOT}/systemctl.log"
    [[ "$STAGE" == "start" || "$STAGE" == "clonestart" ]] && [[ "${1:-}" == "start" ]] && return 1
    return 0
}

require_remote_branch() { :; }
check_active_xo_tasks() { :; }
snapshot_xo_vm() { :; }
get_installed_commit() { echo "aaaaaaaaaaaaaaaa"; }
get_remote_commit() { echo "bbbbbbbbbbbbbbbb"; }
prompt_yes_no() { return 0; }
get_previous_service_user() { echo "$SERVICE_USER"; }
detect_nodejs_drift() { :; }
install_nodejs() { :; }
install_yarn() { :; }
create_systemd_service() { :; }
configure_sudo() { :; }
configure_xenstore_access() { :; }
cleanup_stale_service_user() { :; }
configure_firewall() { :; }
wait_for_xo_ready() { :; }

install_dir_git() {
    case "${1:-}" in
        rev-parse) echo "master" ;;
        fetch) [[ "$STAGE" != "pull" ]] ;;
        *) return 0 ;;
    esac
}
flush_redis_tokens() { [[ "$STAGE" != "flush" ]]; }
build_xo() { [[ "$STAGE" != "build" ]]; }
if [[ "$STAGE" == "backup" ]]; then
    # Fail the copy inside the real create_backup.
    mkdir() { [[ "${*: -1}" != "$BACKUP_DIR" ]] && command mkdir "$@"; }
fi

case "$OPERATION" in
    update) update_xo ;;
    rebuild) rebuild_xo ;;
    restore)
        NON_INTERACTIVE=true
        RESTORE_BACKUP_FILE="$STAGE"
        STAGE=none
        restore_xo
        ;;
    *) echo "unknown operation: $OPERATION" >&2; exit 64 ;;
esac
