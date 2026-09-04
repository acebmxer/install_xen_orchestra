#!/bin/bash
set -euo pipefail

# Enable debug mode if XO_DEBUG environment variable is set
# Note: sensitive variables (passwords, tokens) are masked in debug output
if [[ "${XO_DEBUG:-0}" == "1" ]]; then
    set -x
    # Mask sensitive variables from debug trace output
    export PS4='+ '
fi

trap 'log_error "Script failed at line $LINENO: $BASH_COMMAND. If the service was stopped, run: sudo systemctl start xo-server"' ERR
#
# Xen Orchestra Installation Script
# Based on: https://docs.xen-orchestra.com/install-from-sources
#
# This script installs Xen Orchestra from source with:
# - Node.js (latest LTS by default; configurable via NODE_VERSION in xo-config.cfg)
# - Self-signed SSL certificate
# - Direct ports 80/443 (no proxy)
# - Systemd service management
# - Update functionality with backup management
# - Restore functionality from named backups
# - Rebuild functionality (fresh clone + build, preserves settings)
#

# Script directory and self-update support
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"
ORIGINAL_ARGS=("$@")
CONFIG_FILE="${SCRIPT_DIR}/xo-config.cfg"
SAMPLE_CONFIG="${SCRIPT_DIR}/sample-xo-config.cfg"
LATEST_CONFIG_VERSION=3

# Runtime mode flags (set via CLI flags in main())
NON_INTERACTIVE=false
RESTORE_BACKUP_FILE=""
DRY_RUN=false
ALLOW_EOL_DISTRO=false

# Logging flags (set via CLI flags in main())
LOG_FILE=""
JSON_LOGS=false

# Lockfile path — prevents two concurrent runs from corrupting the install
XO_LOCKFILE="/var/lock/xo-install.lock"
# File descriptor used by flock (assigned in acquire_lock)
XO_LOCK_FD=9

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Internal log dispatcher — all log_* functions funnel through here.
# Arguments: level  message
# Outputs:   ANSI human-readable line to stderr (always)
#            Plain-text line to LOG_FILE when set
#            JSON line to LOG_FILE when JSON_LOGS=true
_log() {
    local level="$1"
    local msg="$2"
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Choose ANSI colour based on level
    local colour
    case "$level" in
        INFO)    colour="$BLUE" ;;
        SUCCESS) colour="$GREEN" ;;
        WARNING) colour="$YELLOW" ;;
        ERROR)   colour="$RED" ;;
        *)       colour="$NC" ;;
    esac

    # Human-readable output to stdout
    echo -e "${colour}[${level}]${NC} ${msg}"

    # File output (plain-text or JSON)
    if [[ -n "$LOG_FILE" ]]; then
        if [[ "$JSON_LOGS" == "true" ]]; then
            # Escape backslashes and double-quotes in the message for JSON
            local json_msg="${msg//\\/\\\\}"
            json_msg="${json_msg//\"/\\\"}"
            printf '{"ts":"%s","level":"%s","msg":"%s"}\n' \
                "$ts" "$level" "$json_msg" >> "$LOG_FILE"
        else
            printf '[%s] [%s] %s\n' "$ts" "$level" "$msg" >> "$LOG_FILE"
        fi
    fi
}

log_info() {
    _log "INFO" "$1"
}

log_success() {
    _log "SUCCESS" "$1"
}

log_warning() {
    _log "WARNING" "$1"
}

log_error() {
    _log "ERROR" "$1"
}

# Acquire an exclusive lock on XO_LOCKFILE using flock.
# The lock is held on file descriptor XO_LOCK_FD for the lifetime of the
# process.  A trap ensures the lock is always released on exit/signal.
acquire_lock() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Would acquire lock: $XO_LOCKFILE"
        return 0
    fi

    # Create the lockfile if it doesn't exist (requires /var/lock to exist)
    if ! sudo touch "$XO_LOCKFILE" 2>/dev/null; then
        log_warning "Could not create $XO_LOCKFILE; proceeding without lock."
        return 0
    fi
    # Ensure the current (non-root) user can open the lockfile for flock
    sudo chmod 666 "$XO_LOCKFILE" 2>/dev/null || true

    # Open the lockfile on fd XO_LOCK_FD
    eval "exec ${XO_LOCK_FD}>'${XO_LOCKFILE}'" 2>/dev/null || {
        log_warning "Could not open $XO_LOCKFILE for locking; proceeding without lock."
        return 0
    }

    if ! flock -n "$XO_LOCK_FD" 2>/dev/null; then
        log_error "Another instance of this script is already running."
        log_error "If you are sure no other instance is running, remove: $XO_LOCKFILE"
        exit 1
    fi

    # Write our PID into the lockfile so operators can identify the holder
    { echo "$$" >&"$XO_LOCK_FD"; } 2>/dev/null || true

    # Release the lock on any exit
    trap 'flock -u '"$XO_LOCK_FD"' 2>/dev/null || true' EXIT
}

# Explicitly release the lock (called just before exec-restart so the child
# can re-acquire it).
release_lock() {
    flock -u "$XO_LOCK_FD" 2>/dev/null || true
}

# In non-interactive mode auto-confirms and returns 0; otherwise prompts [y/N].
# Usage: confirm_or_skip "Description" || { log_info "Cancelled."; exit 0; }
confirm_or_skip() {
    local message="$1"
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        log_info "Non-interactive: auto-confirming: $message"
        return 0
    fi
    echo -n "${message} [y/N]: "
    local reply
    read -t 300 -r reply || { log_error "Input timeout"; exit 1; }
    [[ "$reply" == [Yy] ]]
}

# Strict yes/no prompt: re-asks until the user types y/yes or n/no.
# Unlike confirm_or_skip, blank or garbage input is rejected, not treated as "no".
# Returns 0 for yes, 1 for no. In non-interactive mode auto-answers yes.
# Usage: if prompt_yes_no "Do the thing?"; then ...; fi
prompt_yes_no() {
    local message="$1"
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        log_info "Non-interactive: auto-answering yes: $message"
        return 0
    fi
    local reply
    while true; do
        echo -n "${message} [y/n]: "
        read -t 300 -r reply < /dev/tty || { log_error "Input timeout"; exit 1; }
        case "$reply" in
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo])     return 1 ;;
            *) log_warning "Please answer 'y' or 'n'." ;;
        esac
    done
}

# Execute a command, or in dry-run mode print what would be executed.
# Usage: run_cmd sudo systemctl start xo-server
run_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Would run: $*"
        return 0
    fi
    "$@"
}

# Check if running as root/sudo and refuse
check_not_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "=============================================="
        log_error "Do NOT run this script as root or with sudo!"
        log_error "Run as a normal user - the script will use sudo"
        log_error "internally for commands that require privileges."
        log_error "=============================================="
        exit 1
    fi
}

# Check for required commands at startup
check_required_commands() {
    local missing_commands=()

    for cmd in bash grep sed awk cut; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands+=("$cmd")
        fi
    done

    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        log_error "The following required commands are missing: ${missing_commands[*]}"
        exit 1
    fi
}

# Check if sudo is available and user has sudo privileges
check_sudo() {
    if ! command -v sudo >/dev/null 2>&1; then
        if [[ "${DRY_RUN:-false}" == "true" ]]; then
            log_warning "[DRY-RUN] sudo is not installed; skipping sudo check."
            return 0
        fi
        log_error "sudo is not installed. Please install sudo first."
        exit 1
    fi

    if ! sudo -v >/dev/null 2>&1; then
        if [[ "${DRY_RUN:-false}" == "true" ]]; then
            log_warning "[DRY-RUN] No sudo privileges; skipping sudo check."
            return 0
        fi
        log_error "You need sudo privileges to run this script."
        log_error "Please ensure your user is in the sudoers file."
        exit 1
    fi
}

# Check if git is available
check_git() {
    if ! command -v git >/dev/null 2>&1; then
        log_error "git is not installed. Please install git first."
        exit 1
    fi
}

# Self-update the installation script from git
self_update_script() {
    # Skip self-update if XO_NO_SELF_UPDATE is set
    if [[ "${XO_NO_SELF_UPDATE:-0}" == "1" ]]; then
        return 0
    fi

    # Require git
    if ! command -v git &>/dev/null; then
        log_warning "git is not installed; skipping self-update check."
        return 0
    fi

    # Require script directory to be a git repo
    if [[ ! -d "${SCRIPT_DIR}/.git" ]]; then
        log_warning "Script directory is not a git repository; skipping self-update check."
        return 0
    fi

    log_info "Checking for script updates..."

    # Fetch latest from the current branch
    local current_branch
    current_branch=$(git -C "$SCRIPT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null) || true
    current_branch="${current_branch:-main}"

    if ! git -C "$SCRIPT_DIR" fetch origin "$current_branch" 2>/dev/null; then
        log_warning "Could not check for script updates (network unavailable?)."
        return 0
    fi

    # Record current HEAD
    local before after
    before=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null)

    # Stash any local changes (tracked + untracked) so they don't block the pull.
    # This protects user config files (e.g. xo-config.cfg) from being overwritten.
    local did_stash=false
    if ! git -C "$SCRIPT_DIR" diff --quiet 2>/dev/null || \
       [[ -n "$(git -C "$SCRIPT_DIR" ls-files --others --exclude-standard 2>/dev/null)" ]]; then
        if git -C "$SCRIPT_DIR" stash push --include-untracked -m "self-update auto-stash" 2>/dev/null; then
            did_stash=true
        fi
    fi

    # Attempt fast-forward pull
    local pull_err
    if ! pull_err=$(git -C "$SCRIPT_DIR" pull --ff-only origin "$current_branch" 2>&1); then
        # Restore stashed changes before prompting
        if [[ "$did_stash" == "true" ]]; then
            git -C "$SCRIPT_DIR" stash pop 2>/dev/null || true
            did_stash=false
        fi
        log_warning "Script auto-update failed: $pull_err"
        # Distinguish between file conflicts and diverged history
        if printf '%s' "$pull_err" | grep -qi "untracked working tree files\|would be overwritten"; then
            log_warning "Untracked local files conflict with incoming changes in ${SCRIPT_DIR}."
        elif printf '%s' "$pull_err" | grep -qi "not possible to fast-forward\|diverge"; then
            log_warning "Local branch has diverged from origin/${current_branch}."
        else
            log_warning "Local modifications detected in ${SCRIPT_DIR}."
        fi
        if ! confirm_or_skip "Reset to origin/${current_branch}? Local changes will be lost."; then
            log_warning "Self-update skipped. Continuing with current version."
            return 0
        fi
        git -C "$SCRIPT_DIR" checkout "$current_branch" 2>/dev/null
        git -C "$SCRIPT_DIR" reset --hard "origin/${current_branch}" 2>/dev/null
        git -C "$SCRIPT_DIR" clean -fd 2>/dev/null
        if [[ "$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null)" != \
              "$(git -C "$SCRIPT_DIR" rev-parse "origin/${current_branch}" 2>/dev/null)" ]]; then
            log_warning "Unable to auto-resolve. Continuing with current version."
            return 0
        fi
        log_success "Reset to origin/${current_branch}."
    fi

    # Restore stashed local changes (e.g. xo-config.cfg) after a successful pull
    if [[ "$did_stash" == "true" ]]; then
        if ! git -C "$SCRIPT_DIR" stash pop 2>/dev/null; then
            log_warning "Could not restore local changes automatically."
            log_warning "Your changes are saved in 'git stash'. Run 'git -C ${SCRIPT_DIR} stash pop' to recover them."
        fi
    fi

    after=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null)

    if [[ "$before" != "$after" ]]; then
        log_success "Script updated to $(git -C "$SCRIPT_DIR" rev-parse --short HEAD). Restarting..."
        release_lock
        exec bash "$SCRIPT_PATH" "${ORIGINAL_ARGS[@]}"
    else
        log_info "Script is already up to date."
    fi
    return 0
}

# Check if systemctl is available
check_systemctl() {
    if ! command -v systemctl >/dev/null 2>&1; then
        if [[ "${DRY_RUN:-false}" == "true" ]]; then
            log_warning "[DRY-RUN] systemctl is not available; skipping systemd check."
            return 0
        fi
        log_error "systemctl is not available. This script requires systemd."
        exit 1
    fi
}

# Load configuration
load_config() {
    # Check if config file exists, if not copy from sample
    if [[ ! -f "$CONFIG_FILE" ]]; then
        if [[ -f "$SAMPLE_CONFIG" ]]; then
            log_info "Configuration file not found. Creating from sample..."
            cp "$SAMPLE_CONFIG" "$CONFIG_FILE"
            log_success "Created $CONFIG_FILE from sample-xo-config.cfg"
            log_info "Please review the configuration before proceeding."
        else
            log_error "Neither xo-config.cfg nor sample-xo-config.cfg found!"
            exit 1
        fi
    fi

    # Validate config file ownership and permissions before sourcing
    # The config file is executed as shell code, so it must be owned by
    # the current user or root, and not writable by others.
    local CFG_OWNER CFG_PERMS
    CFG_OWNER=$(stat -c '%U' "$CONFIG_FILE" 2>/dev/null)
    CFG_PERMS=$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null)
    if [[ "$CFG_OWNER" != "$(whoami)" ]] && [[ "$CFG_OWNER" != "root" ]]; then
        log_error "Config file $CONFIG_FILE is owned by '$CFG_OWNER' — must be owned by $(whoami) or root"
        exit 1
    fi
    if [[ "${CFG_PERMS: -1}" =~ [2367] ]]; then
        log_error "Config file $CONFIG_FILE is world-writable (mode $CFG_PERMS) — refusing to source"
        exit 1
    fi

    # Source the configuration
    source "$CONFIG_FILE"

    # Set defaults if not specified
    HTTP_PORT=${HTTP_PORT:-80}
    HTTPS_PORT=${HTTPS_PORT:-443}
    INSTALL_DIR=${INSTALL_DIR:-/opt/xen-orchestra}
    SSL_CERT_DIR=${SSL_CERT_DIR:-/etc/ssl/xo}
    SSL_CERT_FILE=${SSL_CERT_FILE:-xo-cert.pem}
    SSL_KEY_FILE=${SSL_KEY_FILE:-xo-key.pem}
    SSL_CERT_DAYS=${SSL_CERT_DAYS:-825}
    GIT_BRANCH=${GIT_BRANCH:-master}
    BACKUP_DIR=${BACKUP_DIR:-/opt/xo-backups}
    BACKUP_KEEP=${BACKUP_KEEP:-5}
    TURBO_CACHE_ENABLED=${TURBO_CACHE_ENABLED:-true}
    NODE_VERSION=${NODE_VERSION:-24.15.0}
    SERVICE_USER=${SERVICE_USER:-root}
    DEBUG_MODE=${DEBUG_MODE:-false}
    BIND_ADDRESS=${BIND_ADDRESS:-0.0.0.0}
    REDIRECT_TO_HTTPS=${REDIRECT_TO_HTTPS:-false}
    REVERSE_PROXY_TRUST=${REVERSE_PROXY_TRUST:-false}
    PUBLIC_URL=${PUBLIC_URL:-}
    REDIS_URI=${REDIS_URI:-}
    REDIS_SOCKET=${REDIS_SOCKET:-}
    ENCRYPT_REDIS_CREDENTIALS=${ENCRYPT_REDIS_CREDENTIALS:-false}
    DISABLE_WARNINGS=${DISABLE_WARNINGS:-false}
    DISABLE_LICENSE_CHECK=${DISABLE_LICENSE_CHECK:-false}
    PREFERRED_EDITOR=${PREFERRED_EDITOR:-nano}

    # Migrate config schema if needed, then validate
    migrate_config "$CONFIG_FILE"
    validate_config
}

# Validate configuration values
validate_config() {
    local errors=()

    # Validate INSTALL_DIR
    if [[ -z "$INSTALL_DIR" ]]; then
        errors+=("INSTALL_DIR is not set")
    elif [[ "$INSTALL_DIR" != /* ]]; then
        errors+=("INSTALL_DIR must be an absolute path (starting with /)")
    fi

    # Validate ports are numeric
    if ! [[ "$HTTP_PORT" =~ ^[0-9]+$ ]]; then
        errors+=("HTTP_PORT must be a number, got: $HTTP_PORT")
    elif [[ $HTTP_PORT -lt 1 ]] || [[ $HTTP_PORT -gt 65535 ]]; then
        errors+=("HTTP_PORT must be between 1 and 65535, got: $HTTP_PORT")
    fi

    if ! [[ "$HTTPS_PORT" =~ ^[0-9]+$ ]]; then
        errors+=("HTTPS_PORT must be a number, got: $HTTPS_PORT")
    elif [[ $HTTPS_PORT -lt 1 ]] || [[ $HTTPS_PORT -gt 65535 ]]; then
        errors+=("HTTPS_PORT must be between 1 and 65535, got: $HTTPS_PORT")
    fi

    # Validate SERVICE_USER if set
    if [[ -n "$SERVICE_USER" ]]; then
        if ! [[ "$SERVICE_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
            errors+=("SERVICE_USER must be a valid Linux username, got: $SERVICE_USER")
        fi
    fi

    # Validate BACKUP_KEEP is numeric
    if ! [[ "$BACKUP_KEEP" =~ ^[0-9]+$ ]]; then
        errors+=("BACKUP_KEEP must be a number, got: $BACKUP_KEEP")
    elif [[ $BACKUP_KEEP -lt 1 ]]; then
        errors+=("BACKUP_KEEP must be at least 1, got: $BACKUP_KEEP")
    fi

    # Validate NODE_VERSION is a valid version (e.g. 22, 22.3, 22.3.1)
    if ! [[ "$NODE_VERSION" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
        errors+=("NODE_VERSION must be a valid version number (e.g. 22, 22.3), got: $NODE_VERSION")
    fi

    # Validate SSL_CERT_DAYS is a sane certificate lifetime
    if ! [[ "${SSL_CERT_DAYS:-825}" =~ ^[0-9]+$ ]]; then
        errors+=("SSL_CERT_DAYS must be a number, got: ${SSL_CERT_DAYS:-}")
    elif [[ ${SSL_CERT_DAYS:-825} -lt 1 ]]; then
        errors+=("SSL_CERT_DAYS must be at least 1, got: ${SSL_CERT_DAYS:-}")
    fi

    # Validate ENCRYPT_REDIS_CREDENTIALS is a boolean
    if [[ "$ENCRYPT_REDIS_CREDENTIALS" != "true" ]] && [[ "$ENCRYPT_REDIS_CREDENTIALS" != "false" ]]; then
        errors+=("ENCRYPT_REDIS_CREDENTIALS must be true or false, got: $ENCRYPT_REDIS_CREDENTIALS")
    fi

    # Validate TURBO_CACHE_ENABLED is a boolean
    if [[ "$TURBO_CACHE_ENABLED" != "true" ]] && [[ "$TURBO_CACHE_ENABLED" != "false" ]]; then
        errors+=("TURBO_CACHE_ENABLED must be true or false, got: $TURBO_CACHE_ENABLED")
    fi

    # Report errors if any
    if [[ ${#errors[@]} -gt 0 ]]; then
        log_error "Configuration validation failed:"
        for error in "${errors[@]}"; do
            log_error "  - $error"
        done
        exit 1
    fi
}

# Detect legacy system-level security issues from older script versions.
# Populates the global LEGACY_SYSTEM_CHANGES array.
detect_legacy_system_state() {
    LEGACY_SYSTEM_CHANGES=()
    if [[ -n "${SERVICE_USER:-}" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        local SUDOERS_FILE="/etc/sudoers.d/xo-server-${SERVICE_USER}"
        if [[ -f "$SUDOERS_FILE" ]] && grep -q "chmod\|chown\|mkdir\|SETENV" "$SUDOERS_FILE" 2>/dev/null; then
            LEGACY_SYSTEM_CHANGES+=("Sudoers: remove chmod/chown/mkdir/SETENV (keep mount/umount/findmnt per official docs)")
        fi
        if id -nG "$SERVICE_USER" 2>/dev/null | grep -qw root; then
            LEGACY_SYSTEM_CHANGES+=("User: remove ${SERVICE_USER} from root group (no longer needed)")
        fi
    fi
    if [[ -f /etc/systemd/system/xo-server.service ]]; then
        if grep -q "^AmbientCapabilities=.*CAP_SYS_ADMIN" /etc/systemd/system/xo-server.service 2>/dev/null; then
            LEGACY_SYSTEM_CHANGES+=("Systemd: remove CAP_SYS_ADMIN from AmbientCapabilities (should only be in CapabilityBoundingSet)")
        fi
        if grep -q "^Group=root" /etc/systemd/system/xo-server.service 2>/dev/null; then
            LEGACY_SYSTEM_CHANGES+=("Systemd: remove Group=root and SupplementaryGroups=root")
        fi
    fi
}

# Migrate config file to the latest schema version.
# Appends CONFIG_VERSION if missing and surfaces any legacy system-level issues.
migrate_config() {
    local cfg_file="$1"
    local current_ver="${CONFIG_VERSION:-0}"

    if [[ "$current_ver" -ge "$LATEST_CONFIG_VERSION" ]]; then
        return 0
    fi

    log_info "Config schema version ${current_ver} detected; migrating to version ${LATEST_CONFIG_VERSION}..."

    # v0 → v1: no config key renames — just stamp the version and surface
    # any legacy system-level security state that reconfigure_xo() can fix.
    if [[ "$current_ver" -lt 1 ]]; then
        detect_legacy_system_state
        if [[ ${#LEGACY_SYSTEM_CHANGES[@]} -gt 0 ]]; then
            log_warning "Legacy system state detected. Run --reconfigure to apply security hardening:"
            for change in "${LEGACY_SYSTEM_CHANGES[@]}"; do
                log_warning "  - $change"
            done
        fi
        CONFIG_VERSION=1
    fi

    # v1 → v2: add PUBLIC_URL and ENCRYPT_REDIS_CREDENTIALS keys if absent.
    if [[ "$current_ver" -lt 2 ]]; then
        if ! grep -q '^[[:space:]]*PUBLIC_URL=' "$cfg_file" 2>/dev/null; then
            {
                echo ""
                echo "# Public URL advertised to external entities (e.g. XO Lite)"
                echo "# Set this when XO is behind a reverse proxy or reached via a domain name."
                echo "# Example: PUBLIC_URL=https://xo.example.com"
                echo "# PUBLIC_URL="
            } >> "$cfg_file"
        fi
        if ! grep -q '^[[:space:]]*ENCRYPT_REDIS_CREDENTIALS=' "$cfg_file" 2>/dev/null; then
            {
                echo ""
                echo "# Encrypt credentials stored in Redis at rest using AES-256-GCM (true/false)"
                echo "# Only works when XO runs as a VM on a XenServer/XCP-ng host with"
                echo "# xenstore-read/xenstore-write access — NOT on bare metal or other"
                echo "# hypervisors. Set back to false to decrypt and opt out. Default: false"
                echo "#"
                echo "# The default (false) stores XAPI credentials readably. That is expected:"
                echo "# xo-server replays them to XAPI on every reconnect, so they cannot be"
                echo "# hashed. The perimeter is localhost-bound Redis plus root on this VM."
                echo "#"
                echo "# BEFORE ENABLING: the key is split between XenStore and"
                echo "# /var/lib/xo-server/data. Losing either half while encryption is on"
                echo "# makes the records permanently undecryptable, and this script's"
                echo "# --backup does not include either half — use the passphrase-protected"
                echo "# XO config export as your recovery artifact. See the README and"
                echo "# https://docs.xen-orchestra.com/credential-encryption"
                echo "ENCRYPT_REDIS_CREDENTIALS=false"
            } >> "$cfg_file"
        fi
        CONFIG_VERSION=2
    fi

    # v2 → v3: add SSL_CERT_DAYS. Existing installs keep the certificate they
    # already have (generate_ssl_certificate never overwrites one), so this
    # only takes effect when a cert is reissued — but the key needs to be in
    # the file for anyone who goes looking for the knob.
    if [[ "$current_ver" -lt 3 ]]; then
        if ! grep -q '^[[:space:]]*SSL_CERT_DAYS=' "$cfg_file" 2>/dev/null; then
            {
                echo ""
                echo "# Validity of the generated self-signed certificate, in days."
                echo "# 825 is the ceiling most security policies inherited from the"
                echo "# CA/Browser Forum; a longer-lived certificate is a common audit"
                echo "# finding. Existing certificates are never regenerated — delete the"
                echo "# files in SSL_CERT_DIR and run --reconfigure to reissue."
                echo "SSL_CERT_DAYS=825"
            } >> "$cfg_file"
        fi
        CONFIG_VERSION=3
    fi

    # Stamp the new schema version.
    if grep -q '^[[:space:]]*CONFIG_VERSION=' "$cfg_file" 2>/dev/null; then
        sed -i "s/^[[:space:]]*CONFIG_VERSION=.*/CONFIG_VERSION=${LATEST_CONFIG_VERSION}/" "$cfg_file"
    else
        {
            echo ""
            echo "# Config schema version — do not modify manually"
            echo "CONFIG_VERSION=${LATEST_CONFIG_VERSION}"
        } >> "$cfg_file"
    fi
    CONFIG_VERSION=$LATEST_CONFIG_VERSION

    log_success "Config migrated from version ${current_ver} to ${LATEST_CONFIG_VERSION}."
}

# Detect package manager
detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        PKG_INSTALL="sudo apt-get install -y"
        PKG_UPDATE="sudo apt-get update"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        PKG_INSTALL="sudo dnf install -y"
        PKG_UPDATE="sudo dnf makecache"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        PKG_INSTALL="sudo yum install -y"
        PKG_UPDATE="sudo yum makecache"
    else
        log_error "No supported package manager found (apt, dnf, yum)"
        exit 1
    fi
    log_info "Detected package manager: $PKG_MANAGER"
}

# Refresh the package lists, tolerating failure.
#
# A single broken third-party repo (a PPA with no Release file for the running
# release, say) makes apt-get update exit non-zero even though every other
# source refreshed fine. Under `set -e` that aborted the script before it could
# try the install that actually matters -- and the install usually works, since
# the package is in the lists we did manage to fetch, or already cached. So warn
# and carry on; the install is the step allowed to be fatal.
pkg_update_soft() {
    # shellcheck disable=SC2086
    if ! run_cmd $PKG_UPDATE; then
        log_warning "Refreshing the package lists failed (a broken repository, most likely)."
        log_warning "Continuing anyway -- the install below will fail if the package is unreachable."
    fi
}

# Detect OS distribution
detect_os() {
    # OS_VERSION_ID is read by check_eol_distro() below; keep it populated on
    # every path, including the failure paths, so the check never sees a stale
    # value left over from a previous call.
    if [[ -f /etc/os-release ]]; then
        if . /etc/os-release 2>/dev/null; then
            OS_ID="${ID:-unknown}"
            OS_VERSION_ID="${VERSION_ID:-unknown}"
            if [[ "$OS_ID" == "unknown" ]]; then
                log_warning "Could not determine OS ID from /etc/os-release"
            fi
        else
            log_warning "Failed to parse /etc/os-release"
            OS_ID="unknown"
            OS_VERSION_ID="unknown"
        fi
    else
        log_warning "/etc/os-release not found. OS detection may be inaccurate."
        OS_ID="unknown"
        OS_VERSION_ID="unknown"
    fi
}

# End-of-life distribution policy.
#
# Debian 11 (Bullseye) left Debian LTS on 2026-08-31 and receives no further
# security updates. This installer stops supporting it on 2026-10-01: until
# that date a run on Bullseye warns and continues, and from that date it stops
# unless the operator passes --allow-eol-distro.
#
# The cutoff is compared as a plain YYYYMMDD integer against the local clock,
# so a machine with a badly wrong date degrades to the warning rather than to a
# hard stop. Both dates are named here so there is one place to edit when this
# whole block is deleted after the removal lands.
XO_DEBIAN11_EOL_DATE="2026-08-31"
XO_DEBIAN11_REMOVAL_DATE="2026-10-01"
XO_DEBIAN11_REMOVAL_STAMP="20261001"

# Warn on, or refuse to run on, a distribution whose support has been dropped.
# Called from install_dependencies() after detect_os() has populated OS_ID and
# OS_VERSION_ID. Returns 0 when the run may continue; exits 1 when it may not.
check_eol_distro() {
    [[ "$OS_ID" == "debian" && "${OS_VERSION_ID%%.*}" == "11" ]] || return 0

    local today
    today="$(date +%Y%m%d 2>/dev/null || echo 00000000)"

    if (( 10#$today < 10#$XO_DEBIAN11_REMOVAL_STAMP )); then
        log_warning "=============================================="
        log_warning "Debian 11 (Bullseye) reached end-of-life on ${XO_DEBIAN11_EOL_DATE}"
        log_warning "and no longer receives security updates."
        log_warning ""
        log_warning "Support for Debian 11 is being removed from this"
        log_warning "installer on ${XO_DEBIAN11_REMOVAL_DATE}. After that date this"
        log_warning "script will refuse to run on Debian 11."
        log_warning ""
        log_warning "Upgrade to Debian 12 or Debian 13 before then."
        log_warning "=============================================="
        return 0
    fi

    # Past the cutoff. With the override the run continues, so say so without
    # printing the full refusal and telling the operator to pass a flag they
    # have already passed.
    if [[ "$ALLOW_EOL_DISTRO" == true ]]; then
        log_warning "=============================================="
        log_warning "Debian 11 (Bullseye) is no longer supported."
        log_warning "It reached end-of-life on ${XO_DEBIAN11_EOL_DATE} and support was"
        log_warning "removed from this installer on ${XO_DEBIAN11_REMOVAL_DATE}."
        log_warning ""
        log_warning "--allow-eol-distro given; continuing anyway. This"
        log_warning "configuration is untested and unsupported."
        log_warning "=============================================="
        return 0
    fi

    log_error "=============================================="
    log_error "Debian 11 (Bullseye) is no longer supported."
    log_error ""
    log_error "Debian 11 reached end-of-life on ${XO_DEBIAN11_EOL_DATE} and support"
    log_error "was removed from this installer on ${XO_DEBIAN11_REMOVAL_DATE}."
    log_error "It is no longer tested, and Xen Orchestra's own"
    log_error "dependencies are unlikely to install on it."
    log_error ""
    log_error "Upgrade to Debian 12 or Debian 13."
    log_error ""
    log_error "To proceed anyway, at your own risk, re-run with:"
    log_error "  --allow-eol-distro"
    log_error "=============================================="

    exit 1
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."

    detect_os
    check_eol_distro
    pkg_update_soft

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        # Common packages for all Debian/Ubuntu
        local BASE_PACKAGES="apt-transport-https ca-certificates libcap2-bin curl gnupg \
            build-essential redis-server libpng-dev git python3-minimal \
            libvhdi-utils lvm2 cifs-utils nfs-common ntfs-3g openssl \
            dmidecode patch sudo"

        # Add software-properties-common for Ubuntu
        if [[ "$OS_ID" == "ubuntu" ]]; then
            BASE_PACKAGES="$BASE_PACKAGES software-properties-common"
        fi

        # Try to install libfuse2t64 (newer systems) or fall back to libfuse2
        if apt-cache search "^libfuse2t64" 2>/dev/null | grep -q libfuse2t64; then
            # shellcheck disable=SC2086
            run_cmd $PKG_INSTALL $BASE_PACKAGES libfuse2t64
        else
            log_info "libfuse2t64 not available, installing libfuse2 instead..."
            # shellcheck disable=SC2086
            run_cmd $PKG_INSTALL $BASE_PACKAGES libfuse2
        fi

    elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
        # Check if it's RHEL 10+ or similar where Redis is replaced by Valkey
        if [[ "$PKG_MANAGER" == "dnf" ]]; then
            # Check if Redis package exists, fall back to Valkey if not
            if dnf list available 2>/dev/null | grep -q "^redis"; then
                # shellcheck disable=SC2086
                run_cmd $PKG_INSTALL redis
            else
                log_info "Redis not available, installing Valkey as replacement..."
                # EPEL and the CRB/devel repo are RHEL-family only — that is where
                # Valkey lives on RHEL/CentOS/Rocky/Alma. Fedora ships Valkey in its
                # base repositories and has neither repo, so skip them there:
                # `epel-release` errors ("No match for argument") and dnf5's
                # config-manager does not accept `--enable`.
                if [[ "$OS_ID" != "fedora" ]]; then
                    run_cmd sudo dnf install -y epel-release || true
                    run_cmd sudo dnf config-manager --enable devel || true
                fi
                # shellcheck disable=SC2086
                run_cmd $PKG_INSTALL valkey valkey-compat-redis
            fi
        else
            # shellcheck disable=SC2086
            run_cmd $PKG_INSTALL redis
        fi
        # shellcheck disable=SC2086
        run_cmd $PKG_INSTALL libpng-devel git lvm2 cifs-utils make automake gcc gcc-c++ \
            nfs-utils ntfs-3g openssl curl ca-certificates gnupg2 patch sudo dmidecode libcap fuse-libs
    fi

    # ESXi/VMware import needs the `nbdinfo` binary. XO can build it from source,
    # but that path is hard-gated on the xo-server process running as root
    # (packages/xo-server/src/api/esxi.mjs: `id -u` must be 0). A non-root
    # SERVICE_USER can never satisfy that, so provide nbdinfo from the distro
    # package instead — XO checks `which nbdinfo` first and skips the root-only
    # build when the binary already exists on PATH.
    if [[ -n "$SERVICE_USER" && "$SERVICE_USER" != "root" ]]; then
        log_info "Non-root SERVICE_USER: installing nbdinfo for ESXi/VMware import..."
        if [[ "$PKG_MANAGER" == "apt" ]]; then
            # shellcheck disable=SC2086
            run_cmd $PKG_INSTALL libnbd-bin \
                || log_warning "Could not install libnbd-bin; ESXi/VMware import over NBD may be unavailable for non-root SERVICE_USER."
        elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
            # shellcheck disable=SC2086
            run_cmd $PKG_INSTALL libnbd \
                || log_warning "Could not install libnbd; ESXi/VMware import over NBD may be unavailable for non-root SERVICE_USER."
        fi
    fi

    log_success "System dependencies installed"
}

# Check if installed Node.js version satisfies the requirement.
# Returns 0 if installed >= required within the same major version.
# Examples:
#   version_satisfies "22.15.1" "22"     -> true  (major matches)
#   version_satisfies "22.15.1" "22.3"   -> true  (22.15 >= 22.3)
#   version_satisfies "22.1.0"  "22.3"   -> false (22.1 < 22.3)
#   version_satisfies "20.20.1" "22"     -> false (major mismatch)
version_satisfies() {
    local INSTALLED=$1
    local REQUIRED=$2

    local INST_MAJOR INST_MINOR INST_PATCH
    IFS='.' read -r INST_MAJOR INST_MINOR INST_PATCH <<< "$INSTALLED"

    local REQ_MAJOR REQ_MINOR REQ_PATCH
    IFS='.' read -r REQ_MAJOR REQ_MINOR REQ_PATCH <<< "$REQUIRED"

    # Major must match
    [[ "$INST_MAJOR" -ne "$REQ_MAJOR" ]] && return 1

    # If only major specified, major match is enough
    [[ -z "$REQ_MINOR" ]] && return 0

    # Compare minor
    [[ "${INST_MINOR:-0}" -lt "${REQ_MINOR:-0}" ]] && return 1
    [[ "${INST_MINOR:-0}" -gt "${REQ_MINOR:-0}" ]] && return 0

    # Minor matches; if no patch specified, satisfied
    [[ -z "$REQ_PATCH" ]] && return 0

    # Compare patch
    [[ "${INST_PATCH:-0}" -ge "${REQ_PATCH:-0}" ]] && return 0
    return 1
}

# Download and install a specific Node.js version from nodejs.org.
# Usage: install_nodejs_binary "22.3"
# Normalises 22.3 → v22.3.0 and downloads the linux binary tarball.
# Returns 1 if the requested version does not exist upstream.
install_nodejs_binary() {
    local VERSION=$1

    # Detect architecture
    local ARCH
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)        ARCH="x64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l)        ARCH="armv7l" ;;
        *)
            log_warning "Unsupported architecture for direct download: $ARCH"
            return 1
            ;;
    esac

    # Normalise version: 22.3 -> 22.3.0
    local VER_PARTS
    IFS='.' read -ra VER_PARTS <<< "$VERSION"
    local FULL_VERSION="${VER_PARTS[0]}.${VER_PARTS[1]:-0}.${VER_PARTS[2]:-0}"

    local FILENAME="node-v${FULL_VERSION}-linux-${ARCH}.tar.xz"
    local URL="https://nodejs.org/dist/v${FULL_VERSION}/${FILENAME}"

    # Check if the exact version exists
    log_info "Checking for Node.js v${FULL_VERSION} at nodejs.org..."
    if ! curl -fsSL --head "$URL" >/dev/null 2>&1; then
        log_warning "Node.js v${FULL_VERSION} not found at nodejs.org"
        return 1
    fi

    log_info "Downloading Node.js v${FULL_VERSION}..."
    local TMP_DIR
    TMP_DIR=$(mktemp -d --tmpdir nodejs-XXXXXX)
    chmod 700 "$TMP_DIR"

    if ! curl -fsSL "$URL" -o "${TMP_DIR}/${FILENAME}"; then
        rm -rf "$TMP_DIR"
        return 1
    fi

    log_info "Installing Node.js v${FULL_VERSION}..."
    run_cmd sudo tar -xJf "${TMP_DIR}/${FILENAME}" --strip-components=1 -C /usr/local/
    rm -rf "$TMP_DIR"

    # Ensure /usr/local/bin is usable (create symlinks into /usr/bin so
    # scripts that reference /usr/bin/node keep working)
    if [[ ! -e /usr/bin/node ]] || [[ "$(readlink -f /usr/bin/node 2>/dev/null)" != "/usr/local/bin/node" ]]; then
        run_cmd sudo ln -sf /usr/local/bin/node /usr/bin/node
    fi
    if [[ ! -e /usr/bin/npm ]] || [[ "$(readlink -f /usr/bin/npm 2>/dev/null)" != "/usr/local/bin/npm" ]]; then
        run_cmd sudo ln -sf /usr/local/bin/npm /usr/bin/npm
    fi
    if [[ ! -e /usr/bin/npx ]] || [[ "$(readlink -f /usr/bin/npx 2>/dev/null)" != "/usr/local/bin/npx" ]]; then
        run_cmd sudo ln -sf /usr/local/bin/npx /usr/bin/npx
    fi
    if [[ -f /usr/local/bin/corepack ]] && { [[ ! -e /usr/bin/corepack ]] || [[ "$(readlink -f /usr/bin/corepack 2>/dev/null)" != "/usr/local/bin/corepack" ]]; }; then
        run_cmd sudo ln -sf /usr/local/bin/corepack /usr/bin/corepack
    fi

    # Clear npm cache — stale cache from the previously package-managed npm
    # causes "Class extends value undefined" errors when installing global packages.
    run_cmd sudo npm cache clean --force 2>/dev/null || true

    return 0
}

# Remove any existing Node.js installation (binary or package) to allow
# clean upgrades, downgrades, and switches between install methods.
remove_existing_nodejs() {
    # Remove binary-installed Node.js from /usr/local
    if [[ -x /usr/local/bin/node ]]; then
        log_info "Removing binary-installed Node.js from /usr/local..."
        run_cmd sudo rm -f /usr/local/bin/node /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
        for bin in node npm npx corepack; do
            if [[ -L /usr/bin/$bin ]] && [[ "$(readlink -f /usr/bin/$bin 2>/dev/null)" == "/usr/local/bin/$bin" ]]; then
                run_cmd sudo rm -f /usr/bin/$bin
            fi
        done
    fi

    # Remove package-managed Node.js
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        if dpkg -l nodejs 2>/dev/null | grep -q '^ii'; then
            log_info "Removing package-managed Node.js..."
            run_cmd sudo apt-get remove -y nodejs 2>/dev/null || true
        fi
    elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
        if rpm -q nodejs &>/dev/null; then
            log_info "Removing package-managed Node.js..."
            run_cmd sudo "$PKG_MANAGER" remove -y nodejs 2>/dev/null || true
        fi
    fi

    # Clean up leftover global node_modules (e.g. yarn) that prevent
    # dpkg from removing the directory cleanly. These will be
    # reinstalled after the new Node.js is in place.
    if [[ -d /usr/lib/node_modules ]]; then
        run_cmd sudo rm -rf /usr/lib/node_modules
    fi

    # Remove NodeSource repository entries so the new version's repo is the only one
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        run_cmd sudo rm -f /etc/apt/sources.list.d/nodesource*.list 2>/dev/null || true
        run_cmd sudo rm -f /etc/apt/keyrings/nodesource.gpg 2>/dev/null || true
    elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
        run_cmd sudo rm -f /etc/yum.repos.d/nodesource*.repo 2>/dev/null || true
    fi
}

# Install Node.js to satisfy NODE_VERSION from xo-config.cfg.
#  - Major-only (e.g. 22):   installs latest 22.x via NodeSource
#  - Specific  (e.g. 22.3):  downloads exact v22.3.0 from nodejs.org;
#                             falls back to latest 22.x via NodeSource
#                             if that version doesn't exist
install_nodejs() {
    log_info "Installing Node.js ${NODE_VERSION}..."

    NODE_MAJOR=${NODE_VERSION%%.*}

    # Check if the currently installed version already satisfies the requirement
    if command -v node >/dev/null 2>&1; then
        local CURRENT_FULL
        CURRENT_FULL=$(node -v | sed 's/^v//')
        if version_satisfies "$CURRENT_FULL" "$NODE_VERSION"; then
            log_info "Node.js ${NODE_VERSION} requirement satisfied (installed: v${CURRENT_FULL})"
            command -v npm >/dev/null 2>&1 && log_info "npm is available: $(npm -v)"
            return 0
        fi
        log_warning "Node.js v${CURRENT_FULL} is installed but does not satisfy version ${NODE_VERSION}"
    fi

    # Remove existing Node.js (binary and/or package) to ensure clean install
    remove_existing_nodejs

    # If a specific minor/patch version was requested, try a direct download first
    if [[ "$NODE_VERSION" == *.* ]]; then
        if install_nodejs_binary "$NODE_VERSION"; then
            log_success "Node.js installed: $(node -v)"
            log_success "npm installed: $(npm -v)"
            return 0
        fi
        log_warning "Falling back to latest ${NODE_MAJOR}.x via NodeSource..."
    fi

    # Install latest in the major series via NodeSource
    # Download setup script to a file first for auditability instead of piping to shell
    local NODESOURCE_SCRIPT
    NODESOURCE_SCRIPT=$(mktemp --tmpdir nodesource-setup-XXXXXX.sh)
    chmod 600 "$NODESOURCE_SCRIPT"

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        local NODESOURCE_URL="https://deb.nodesource.com/setup_${NODE_MAJOR}.x"
    elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
        local NODESOURCE_URL="https://rpm.nodesource.com/setup_${NODE_MAJOR}.x"
    fi

    log_info "Downloading NodeSource setup script..."
    if ! curl -fsSL "$NODESOURCE_URL" -o "$NODESOURCE_SCRIPT"; then
        rm -f "$NODESOURCE_SCRIPT"
        log_error "Failed to download NodeSource setup script"
        return 1
    fi

    log_info "NodeSource setup script saved to $NODESOURCE_SCRIPT for review"
    run_cmd sudo bash "$NODESOURCE_SCRIPT"
    rm -f "$NODESOURCE_SCRIPT"

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        run_cmd sudo apt-get install -y nodejs
    elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
        # shellcheck disable=SC2086
        run_cmd $PKG_INSTALL nodejs
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        echo "[DRY-RUN] Would verify Node.js ${NODE_VERSION} installation"
        return 0
    fi

    # Verify the installed version actually matches what we requested
    local INSTALLED_FULL
    INSTALLED_FULL=$(node -v 2>/dev/null | sed 's/^v//')
    if ! version_satisfies "$INSTALLED_FULL" "$NODE_VERSION"; then
        log_error "Node.js installation failed: expected ${NODE_VERSION}.x but got v${INSTALLED_FULL}"
        log_error "Check for conflicting Node.js installations: 'which -a node'"
        return 1
    fi

    log_success "Node.js installed: $(node -v)"
    log_success "npm installed: $(npm -v)"
}

# Install Yarn
install_yarn() {
    log_info "Installing Yarn..."

    if command -v yarn >/dev/null 2>&1; then
        log_info "Yarn is already installed: $(yarn -v)"
        return 0
    fi

    # npm 11+ (shipped with Node 22+) broke `npm install -g yarn` for yarn v1.
    # Use corepack instead — it ships with Node.js >= 16 and is the recommended way.
    if command -v corepack >/dev/null 2>&1; then
        run_cmd sudo corepack enable
        run_cmd sudo corepack prepare yarn@stable --activate
    else
        run_cmd sudo npm install -g yarn
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        echo "[DRY-RUN] Would verify yarn installation"
        return 0
    fi

    log_success "Yarn installed: $(yarn -v)"
}

# Create service user if needed
create_service_user() {
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        if ! id "$SERVICE_USER" &>/dev/null; then
            log_info "Creating service user: $SERVICE_USER"
            run_cmd sudo useradd -r -m -s /bin/bash "$SERVICE_USER" || true
            log_success "Service user created: $SERVICE_USER"
        else
            log_info "Service user $SERVICE_USER already exists"
        fi

        # Display UID/GID for reference
        local XO_UID XO_GID
        XO_UID=$(id -u "$SERVICE_USER" 2>/dev/null || echo "unknown")
        XO_GID=$(id -g "$SERVICE_USER" 2>/dev/null || echo "unknown")
        log_info "Service user UID:GID is ${XO_UID}:${XO_GID}"
    fi
}

# Flush session tokens from Redis, preserving API tokens used by third-party integrations.
#
# XO stores two categories of tokens under xo:token:*, distinguished by the
# presence of a 'client_id' field in the token JSON:
#   - Session tokens (created at browser login) — HAVE 'client_id' (and a
#     'client' object); their 'description' holds the browser User-Agent.
#   - API tokens (created via Settings > Tokens) — have NO 'client_id'; their
#     'description' is the human-entered label (or empty).
#
# NOTE: classification is by 'client_id', NOT by 'description'. XO stores the
# User-Agent string in 'description' for session tokens, so a non-empty
# description does not mean a token is an API token — earlier versions of this
# function mis-classified every session token as an API token and never flushed
# them, leaving stale tokens that cause "had no attached entries" 401 noise.
#
# Only session tokens become invalid after an XO schema change; API tokens are
# long-lived and must survive an update so that third-party integrations,
# scripts, and the XO_TASK_CHECK_TOKEN used by this installer are not broken.
#
# Called before any xo-server restart that may involve a code change (update,
# rebuild, reconfigure) to eliminate schema-mismatched session tokens that
# would otherwise cause "Cannot destructure property 'client' of 'token'" 401s.
flush_redis_tokens() {
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY-RUN] Would flush browser session tokens from Redis (API tokens are preserved)"
        return 0
    fi

    if ! command -v redis-cli >/dev/null 2>&1; then
        log_warning "redis-cli not found — skipping token flush"
        return 0
    fi

    if ! timeout 5 redis-cli ping 2>/dev/null | grep -q PONG; then
        log_warning "Redis not responding — skipping token flush"
        return 0
    fi

    local -a token_keys
    mapfile -t token_keys < <(redis-cli KEYS "xo:token:*" 2>/dev/null)
    local total=${#token_keys[@]}

    if [[ $total -eq 0 ]]; then
        log_info "No Redis auth tokens found"
        return 0
    fi

    local deleted=0 kept=0
    for key in "${token_keys[@]}"; do
        local raw client_id description

        # Index/metadata keys (double colon in name, e.g. xo:token::indexes) are
        # Redis collection internals that map user IDs to token IDs. Delete them
        # so XO rebuilds clean indexes from the surviving tokens on restart.
        # Stale index entries pointing to deleted tokens cause:
        #   "Cannot destructure property 'client' of 'token' as it is undefined"
        if [[ "$key" == *"::"* ]]; then
            redis-cli DEL "$key" >/dev/null 2>&1
            log_info "  Deleted stale collection index: ${key}"
            continue
        fi

        raw=$(redis-cli GET "$key" 2>/dev/null)

        # Safety: if the value is empty or not valid JSON the token data may be
        # encrypted (XO upstream adds opt-in AES-256-GCM Redis encryption).
        # Preserve the token rather than misidentifying it as a session token.
        if [[ -z "$raw" ]]; then
            log_warning "  Token key ${key} has no data — skipping"
            continue
        fi
        if command -v jq >/dev/null 2>&1; then
            if ! printf '%s' "$raw" | jq empty 2>/dev/null; then
                log_warning "  Token key ${key} is not valid JSON (may be encrypted) — preserving"
                (( kept++ )) || true
                continue
            fi
        fi

        # Classify by the presence of a 'client_id' field:
        #   - has client_id  -> browser session token -> flush
        #   - no  client_id  -> API token             -> preserve
        # 'description' is NOT used to classify — XO puts the User-Agent there
        # for session tokens, so it is non-empty on both kinds.
        if command -v jq >/dev/null 2>&1; then
            client_id=$(printf '%s' "$raw" | jq -r '.client_id // empty' 2>/dev/null || true)
            description=$(printf '%s' "$raw" | jq -r '.description // empty' 2>/dev/null || true)
        else
            # Fallback: detect the "client_id" key; extract description for logging.
            client_id=$(printf '%s' "$raw" | grep -o '"client_id":"[^"]*"' | sed 's/"client_id":"//;s/"//' 2>/dev/null || true)
            description=$(printf '%s' "$raw" | grep -o '"description":"[^"]*"' | sed 's/"description":"//;s/"//' 2>/dev/null || true)
        fi

        if [[ -n "$client_id" ]]; then
            redis-cli DEL "$key" >/dev/null 2>&1
            log_info "  Flushed browser session token (client_id ${client_id})"
            (( deleted++ )) || true
        else
            log_info "  Preserving API token (\"${description:-no description}\")"
            (( kept++ )) || true
        fi
    done

    [[ $deleted -gt 0 ]] && log_info "Flushed ${deleted} session token(s) — users will need to log in again" || true
    [[ $kept -gt 0 ]]    && log_info "Preserved ${kept} API token(s) — third-party integrations unaffected" || true
    [[ $deleted -eq 0 && $kept -eq 0 ]] && log_info "No session tokens to flush" || true
}

# Scan Redis auth tokens for records that reference a user that no longer exists.
#
# Restoring an exported XO config onto a fresh instance is the common cause:
# the export is a point-in-time snapshot, so a token body can land in the new
# Redis with a user_id whose xo:user:<id> record was not restored. Calls using
# such a token fail with "[GET] ... (401)" and XO logs index inconsistencies.
#
# Note: XO's xo:token::indexes SET lists indexed *field names* (client_id,
# user_id), not token IDs — it is collection metadata and is intentionally not
# inspected here. Stale index state is cleared wholesale by flush_redis_tokens(),
# which deletes the ::indexes key so XO rebuilds it on restart.
#
# This is a non-destructive diagnostic — it only reports. Use --flush-tokens
# (or let the next update's flush_redis_tokens() run) to clear orphaned tokens.
check_orphaned_tokens() {
    if ! command -v redis-cli >/dev/null 2>&1; then
        return 0
    fi
    if ! timeout 5 redis-cli ping 2>/dev/null | grep -q PONG; then
        return 0
    fi

    local orphans=0

    # Token bodies referencing a missing user.
    local -A valid_users=()
    local user_key uid
    while IFS= read -r user_key; do
        [[ "$user_key" == *"::"* ]] && continue
        uid="${user_key#xo:user:}"
        [[ "$uid" == "version" ]] && continue
        valid_users["$uid"]=1
    done < <(redis-cli KEYS "xo:user:*" 2>/dev/null)

    # Only run the user check if we actually read some users — an empty result
    # likely means a failed read, and would flag every token as a false positive.
    if [[ ${#valid_users[@]} -gt 0 ]]; then
        local -a token_keys
        mapfile -t token_keys < <(redis-cli KEYS "xo:token:*" 2>/dev/null)

        local key raw token_uid
        for key in "${token_keys[@]}"; do
            [[ "$key" == *"::"* ]] && continue
            [[ "$key" == "xo:token:version" ]] && continue

            raw=$(redis-cli GET "$key" 2>/dev/null)
            [[ -z "$raw" ]] && continue

            if command -v jq >/dev/null 2>&1; then
                printf '%s' "$raw" | jq empty 2>/dev/null || continue
                token_uid=$(printf '%s' "$raw" | jq -r '.user_id // empty' 2>/dev/null || true)
            else
                token_uid=$(printf '%s' "$raw" | grep -o '"user_id":"[^"]*"' | sed 's/"user_id":"//;s/"//' 2>/dev/null || true)
            fi

            [[ -z "$token_uid" ]] && continue
            if [[ -z "${valid_users[$token_uid]:-}" ]]; then
                log_warning "  Orphaned token ${key} references missing user ${token_uid}"
                (( orphans++ )) || true
            fi
        done
    fi

    if [[ $orphans -gt 0 ]]; then
        log_warning "Found ${orphans} auth token(s) referencing users that no longer exist."
        log_warning "This is common after restoring an exported XO config onto a new instance."
        log_warning "Run '${0} --flush-tokens' to clear them and stop the log noise."
    fi
    return 0
}

# Standalone entry point for flushing stale Redis auth tokens without an update.
# flush_redis_tokens() otherwise only runs as a side effect of update/rebuild/
# reconfigure (which require a pending code change). A config restore can leave
# stale token/index records behind with no such change pending — this gives the
# user a direct way to clean them up.
flush_tokens_standalone() {
    log_info "Flushing stale Redis auth tokens..."
    printf '\n'
    check_orphaned_tokens
    flush_redis_tokens
    printf '\n'
    log_info "Restart xo-server for XO to rebuild clean token indexes:"
    log_info "  sudo systemctl restart xo-server"
    log_success "Token flush complete."
}

# Start and enable Redis
setup_redis() {
    log_info "Setting up Redis..."

    check_systemctl

    # A redis/valkey unit may have just been installed; make sure systemd sees it
    # before we probe for it.
    run_cmd sudo systemctl daemon-reload 2>/dev/null || true

    # Detect whichever redis-compatible service this distro installed:
    #   Debian/Ubuntu -> redis-server    RHEL/CentOS -> redis
    #   Fedora / newer RHEL -> valkey (drop-in replacement for redis)
    # `systemctl cat` succeeds only when the unit file actually exists, which is a
    # more reliable test than grepping `list-unit-files` output.
    local redis_svc=""
    local candidate
    for candidate in redis-server redis valkey valkey-server; do
        if systemctl cat "${candidate}.service" >/dev/null 2>&1; then
            redis_svc="$candidate"
            break
        fi
    done

    if [[ -n "$redis_svc" ]]; then
        log_info "Enabling and starting ${redis_svc}.service"
        run_cmd sudo systemctl enable "$redis_svc" 2>/dev/null || true
        run_cmd sudo systemctl start "$redis_svc" 2>/dev/null || true
    else
        log_warning "No redis/valkey systemd unit found; probing for a running server anyway"
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        echo "[DRY-RUN] Would verify Redis is running"
        return 0
    fi

    # Verify the server responds. valkey-compat-redis provides a redis-cli symlink;
    # fall back to valkey-cli if only that is present.
    local redis_cli=""
    if command -v redis-cli >/dev/null 2>&1; then
        redis_cli="redis-cli"
    elif command -v valkey-cli >/dev/null 2>&1; then
        redis_cli="valkey-cli"
    fi

    if [[ -n "$redis_cli" ]] && "$redis_cli" ping 2>/dev/null | grep -q PONG; then
        log_success "Redis is running (${redis_svc:-server}, via ${redis_cli})"
    else
        log_error "Redis/Valkey is not running or not responding"
        log_error "  Detected service: ${redis_svc:-none found}"
        log_error "  Inspect with: sudo systemctl status ${redis_svc:-valkey} --no-pager"
        log_error "                sudo journalctl -u ${redis_svc:-valkey} -n 30 --no-pager"
        exit 1
    fi
}

# Clone or update Xen Orchestra repository
clone_repository() {
    log_info "Setting up Xen Orchestra repository..."

    if [[ -d "$INSTALL_DIR" ]]; then
        log_info "Installation directory exists. Use --update to update."
        return 0
    fi

    run_cmd sudo mkdir -p "$(dirname "$INSTALL_DIR")"

    log_info "Cloning Xen Orchestra (branch: $GIT_BRANCH)..."
    run_cmd sudo git clone -b "$GIT_BRANCH" https://github.com/vatesfr/xen-orchestra "$INSTALL_DIR"

    # Set ownership if service user is defined
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
        run_cmd sudo chmod -R o-rwx "$INSTALL_DIR"
    fi

    log_success "Repository cloned to $INSTALL_DIR"
}

# Build Xen Orchestra
# Ensure swap space exists to prevent OOM during builds
ensure_swap_space() {
    local MIN_SWAP_MB=2048
    local SWAP_FILE="/swapfile"
    
    # Check current swap
    local CURRENT_SWAP
    # Fall back to 0 if free/awk is unavailable (e.g. minimal images without
    # procps-ng) so a missing command can't abort the script under `set -e`.
    CURRENT_SWAP=$(free -m | awk '/^Swap:/ {print $2}') || CURRENT_SWAP=0
    
    # free -m reports slightly less than the file size (mkswap header + MB
    # rounding): a 2048MB swap file shows as 2047MB. Tolerate a small shortfall
    # so the swap file isn't deleted and recreated on every run.
    if [[ $CURRENT_SWAP -ge $((MIN_SWAP_MB - 16)) ]]; then
        log_info "Sufficient swap space available: ${CURRENT_SWAP}MB"
        return 0
    fi
    
    log_warning "Insufficient swap space (${CURRENT_SWAP}MB). Creating ${MIN_SWAP_MB}MB swap file..."
    
    # Check if swap file already exists
    if [[ -f "$SWAP_FILE" ]]; then
        log_info "Removing existing swap file..."
        run_cmd sudo swapoff "$SWAP_FILE" 2>/dev/null || true
        run_cmd sudo rm -f "$SWAP_FILE"
    fi

    # Create swap file
    run_cmd sudo fallocate -l "${MIN_SWAP_MB}M" "$SWAP_FILE" 2>/dev/null || run_cmd sudo dd if=/dev/zero of="$SWAP_FILE" bs=1M count="$MIN_SWAP_MB" status=progress
    run_cmd sudo chmod 600 "$SWAP_FILE"
    run_cmd sudo mkswap "$SWAP_FILE"
    run_cmd sudo swapon "$SWAP_FILE"

    # Make it persistent across reboots
    if ! grep -q "$SWAP_FILE" /etc/fstab 2>/dev/null; then
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "[DRY-RUN] Would append '$SWAP_FILE none swap sw 0 0' to /etc/fstab"
        else
            echo "$SWAP_FILE none swap sw 0 0" | sudo tee -a /etc/fstab > /dev/null
        fi
    fi
    
    log_success "Swap space created: ${MIN_SWAP_MB}MB"
}

# Check that every JS chunk referenced in xo-web's index.html exists on disk.
# After a Vite or build-tool version bump the chunk hashes change; if the
# Vite cache served a stale index.html the browser requests files that were
# never written, getting HTML (the SPA catch-all) instead of JS.
# Called at the end of build_xo — warns and suggests --rebuild if mismatches found.
verify_xo_web_build() {
    # XO now serves two web UIs:
    #   /    → @xen-orchestra/web/dist  (XO 6, default)
    #   /v5  → packages/xo-web/dist    (XO 5, legacy)
    # Check both; warn if either has index.html but missing JS chunks.
    # NOTE: $INSTALL_DIR is typically owned by SERVICE_USER with restrictive
    # permissions, so we use `sudo test`/`sudo grep` for filesystem checks —
    # plain bash `[[ -f ]]` would return false for an existing-but-unreadable
    # path and produce a false-positive warning.
    local -a web_dists=(
        "$INSTALL_DIR/@xen-orchestra/web/dist"
        "$INSTALL_DIR/packages/xo-web/dist"
    )

    local overall_ok=true
    for web_dist in "${web_dists[@]}"; do
        sudo test -f "${web_dist}/index.html" || continue

        local missing=0
        while IFS= read -r chunk; do
            [[ -z "$chunk" ]] && continue
            if ! sudo test -f "${web_dist}/${chunk}"; then
                log_warning "  Missing build artifact in ${web_dist}: ${chunk}"
                (( missing++ )) || true
            fi
        done < <(sudo grep -o 'assets/[a-zA-Z0-9._-]*\.js' "${web_dist}/index.html" 2>/dev/null | sort -u)

        if [[ $missing -gt 0 ]]; then
            log_warning "Build verification: ${missing} JS chunk(s) missing in $(basename "$web_dist")."
            overall_ok=false
        else
            log_info "Build verification passed: $(basename "$web_dist") — all JS chunks present."
        fi
    done

    if [[ "$overall_ok" == "false" ]]; then
        log_warning "Run '--rebuild' to force a clean rebuild."
    fi

    local xo6_dist="$INSTALL_DIR/@xen-orchestra/web/dist"
    if ! sudo test -f "$xo6_dist/index.html"; then
        log_warning "XO 6 web UI artifact missing: $xo6_dist/index.html"
        log_warning "Browser will fall back to XO 5 UI at /v5 if served."
        log_info  "Diagnostic — state of $xo6_dist:"
        if sudo test -d "$xo6_dist"; then
            sudo ls -la "$xo6_dist" 2>&1 | sed 's/^/    /' | while IFS= read -r line; do log_info "$line"; done
        else
            log_info "    (directory does not exist)"
        fi
        log_info  "Diagnostic — state of $INSTALL_DIR/@xen-orchestra/web:"
        if sudo test -d "$INSTALL_DIR/@xen-orchestra/web"; then
            sudo ls -la "$INSTALL_DIR/@xen-orchestra/web" 2>&1 | sed 's/^/    /' | while IFS= read -r line; do log_info "$line"; done
        else
            log_info "    (directory does not exist)"
        fi
        log_warning "Run '--rebuild' to force a clean rebuild if this persists."
    fi
}

# Write an untracked packages/xo-web/turbo.json adding GIT_HEAD to the cache
# key of xo-web's build task (see the rationale in build_xo).  Untracked files
# survive the `git checkout .` and `git checkout -B` in update_xo, and the
# script never runs `git clean`, so this persists across updates.  Written
# idempotently so it doesn't churn xo-web's package hash on every build.
pin_xo_web_cache_key() {
    local xo_web_dir="$INSTALL_DIR/packages/xo-web"
    sudo test -d "$xo_web_dir" || return 0

    local cfg="$xo_web_dir/turbo.json"
    # "extends": ["//"] is required of every package-level turbo.json; "tasks"
    # is the turbo 2 spelling of what turbo 1 called "pipeline".
    local desired='{"extends":["//"],"tasks":{"build":{"env":["GIT_HEAD"]}}}'

    if [[ "$(sudo cat "$cfg" 2>/dev/null)" == "$desired" ]]; then
        return 0
    fi

    if printf '%s\n' "$desired" | sudo -u "${SERVICE_USER:-root}" tee "$cfg" >/dev/null 2>&1; then
        log_info "Pinned xo-web's build cache key to the checked-out commit"
    else
        log_warning "Could not write $cfg — the XO 5 About page may report a stale commit"
    fi
}

# Usage: build_xo [clean]
# If "clean" is passed, turbo cache will be cleared first
build_xo() {
    local CLEAN_BUILD="${1:-}"
    
    log_info "Building Xen Orchestra (this may take a while)..."

    # Ensure swap space exists to prevent OOM
    ensure_swap_space

    # Clear turbo cache if clean build requested.  Turbo 2 keeps the filesystem
    # cache in .turbo/cache; node_modules/.cache/turbo is the turbo 1 location,
    # removed only so a downgrade can't resurrect a stale cache.
    if [[ "$CLEAN_BUILD" == "clean" ]]; then
        log_info "Clearing build cache for clean rebuild..."
        if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
            run_cmd sudo -u "$SERVICE_USER" rm -rf "$INSTALL_DIR/node_modules/.cache/turbo" 2>/dev/null || true
            run_cmd sudo -u "$SERVICE_USER" rm -rf "$INSTALL_DIR/.turbo" 2>/dev/null || true
            run_cmd sudo -u "$SERVICE_USER" rm -rf "$INSTALL_DIR/node_modules/.vite" 2>/dev/null || true
            run_cmd sudo -u "$SERVICE_USER" rm -rf "$INSTALL_DIR/packages/xo-web/node_modules/.vite" 2>/dev/null || true
            run_cmd sudo -u "$SERVICE_USER" rm -rf "$INSTALL_DIR/@xen-orchestra/web/node_modules/.vite" 2>/dev/null || true
        else
            run_cmd sudo rm -rf "$INSTALL_DIR/node_modules/.cache/turbo" 2>/dev/null || true
            run_cmd sudo rm -rf "$INSTALL_DIR/.turbo" 2>/dev/null || true
            run_cmd sudo rm -rf "$INSTALL_DIR/node_modules/.vite" 2>/dev/null || true
            run_cmd sudo rm -rf "$INSTALL_DIR/packages/xo-web/node_modules/.vite" 2>/dev/null || true
            run_cmd sudo rm -rf "$INSTALL_DIR/@xen-orchestra/web/node_modules/.vite" 2>/dev/null || true
        fi
    fi

    # Calculate available memory (RAM + swap) and set build limits to prevent OOM
    local TOTAL_RAM_MB TOTAL_SWAP_MB
    # Fall back to 0 if free/awk is unavailable so a missing command can't abort
    # the build under `set -e`; 0 simply selects the conservative low-memory path.
    TOTAL_RAM_MB=$(free -m | awk '/^Mem:/ {print $2}') || TOTAL_RAM_MB=0
    TOTAL_SWAP_MB=$(free -m | awk '/^Swap:/ {print $2}') || TOTAL_SWAP_MB=0
    local TOTAL_MEM_MB=$((TOTAL_RAM_MB + TOTAL_SWAP_MB))

    local NODE_HEAP_SIZE
    local TURBO_CONCURRENCY
    if [[ $TOTAL_MEM_MB -lt 6144 ]]; then
        # Low memory: conservative settings
        NODE_HEAP_SIZE=1536
        TURBO_CONCURRENCY=1
        log_warning "Low memory detected (${TOTAL_RAM_MB}MB RAM + ${TOTAL_SWAP_MB}MB swap). Limiting build concurrency to 1."
    elif [[ $TOTAL_MEM_MB -lt 10240 ]]; then
        # Moderate memory: limit concurrency
        NODE_HEAP_SIZE=3072
        TURBO_CONCURRENCY=2
        log_info "Moderate memory detected (${TOTAL_RAM_MB}MB RAM + ${TOTAL_SWAP_MB}MB swap). Limiting build concurrency to 2."
    else
        # Plenty of memory
        NODE_HEAP_SIZE=4096
        TURBO_CONCURRENCY=""
    fi

    local NODE_OPTIONS="--max-old-space-size=$NODE_HEAP_SIZE"
    # Local cache lets `--update` reuse unchanged packages' build output
    # instead of rebuilding all 25 every time. `clean` builds (--rebuild)
    # wipe the cache directory before this runs, so they still get a fully
    # fresh build regardless of this setting. Remote is left off since no
    # TURBO_TOKEN/TURBO_TEAM is configured. Controlled by
    # TURBO_CACHE_ENABLED in xo-config.cfg (default: true).
    local TURBO_CACHE="remote:r"
    if [[ "${TURBO_CACHE_ENABLED:-true}" == "true" ]]; then
        TURBO_CACHE="local:rw"
    fi
    # Concurrency must go through the TURBO_CONCURRENCY env var, not
    # `yarn build --concurrency=N`: yarn 1 appends extra args to the END of the
    # script string, and upstream's build script now ends with
    # `&& yarn build:doc`, so a flag would cascade into `docusaurus build`
    # (which rejects it) while turbo itself would never see the limit.
    local BUILD_ENV="NODE_OPTIONS='$NODE_OPTIONS' TURBO_CACHE='$TURBO_CACHE'"
    if [[ -n "$TURBO_CONCURRENCY" ]]; then
        BUILD_ENV="$BUILD_ENV TURBO_CONCURRENCY='$TURBO_CONCURRENCY'"
    fi

    # xo-web bakes the checked-out commit into its bundle at build time:
    #   "build": "GIT_HEAD=$(git rev-parse HEAD) NODE_ENV=production gulp build"
    # and src/xo-app/about/index.js does `const COMMIT_ID = process.env.GIT_HEAD`,
    # which loose-envify inlines as a string literal into dist/index.js.
    #
    # Turbo hashes a package's *files*, not the checked-out commit, and GIT_HEAD
    # is computed by the shell inside that script — after turbo has already
    # decided hit vs. miss.  So an update whose diff doesn't touch
    # packages/xo-web/ gets a cache hit and restores a dist carrying the
    # PREVIOUS commit.  The XO 5 About page then reports the old commit and
    # keeps claiming you're behind master after a successful update.
    #
    # Fix: hand turbo GIT_HEAD explicitly and, via an untracked package-level
    # turbo.json, tell it to fold that value into the cache key for xo-web's
    # build task only.  The commit changes on every update, so xo-web rebuilds
    # every time while the other ~34 tasks stay cached.  Scoping it to xo-web
    # matters: `turbo run build --filter xo-web --force` would also force
    # xo-web's dependencies (--force applies to the whole run), and a
    # root-level globalEnv would bust every package.
    local XO_WEB_HEAD
    XO_WEB_HEAD=$(install_dir_git rev-parse HEAD 2>/dev/null) || XO_WEB_HEAD=""
    if [[ -n "$XO_WEB_HEAD" ]]; then
        BUILD_ENV="$BUILD_ENV GIT_HEAD='$XO_WEB_HEAD'"
        pin_xo_web_cache_key
    fi

    # Patch @xen-orchestra/rest-api's prebuild hook to call rimraf directly instead
    # of `npm run clean`.  When yarn runs the prebuild lifecycle it sets
    # npm_lifecycle_event=prebuild; npm 11 silently exits-1 when asked to run
    # another npm script while that variable is present.  Calling rimraf directly
    # avoids the npm re-entrancy check entirely.  git checkout . before each
    # update reverts this patch automatically.
    local REST_API_DIR="$INSTALL_DIR/@xen-orchestra/rest-api"
    local REST_API_PKG="$REST_API_DIR/package.json"
    if [[ -f "$REST_API_PKG" ]]; then
        local _build_user="${SERVICE_USER:-root}"
        sudo -u "$_build_user" node -e "
            const fs = require('fs');
            const p = JSON.parse(fs.readFileSync('$REST_API_PKG', 'utf8'));
            if (p.scripts && p.scripts.prebuild === 'npm run clean' && p.scripts.clean) {
                p.scripts.prebuild = p.scripts.clean;
                fs.writeFileSync('$REST_API_PKG', JSON.stringify(p, null, 2) + '\n');
            }
        " 2>/dev/null && log_info "Patched @xen-orchestra/rest-api prebuild hook for npm 11 compatibility" || true
    fi

    # Run as service user if defined
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        run_cmd sudo -u "$SERVICE_USER" bash -c "cd '$INSTALL_DIR' && $BUILD_ENV yarn && $BUILD_ENV yarn build"
    else
        run_cmd sudo bash -c "cd '$INSTALL_DIR' && $BUILD_ENV yarn && $BUILD_ENV yarn build"
    fi

    log_success "Xen Orchestra built successfully"
    verify_xo_web_build
}

# Generate self-signed SSL certificate
generate_ssl_certificate() {
    log_info "Generating self-signed SSL certificate..."

    run_cmd sudo mkdir -p "$SSL_CERT_DIR"

    if [[ -f "${SSL_CERT_DIR}/${SSL_CERT_FILE}" ]] && [[ -f "${SSL_CERT_DIR}/${SSL_KEY_FILE}" ]]; then
        log_info "SSL certificates already exist. Skipping generation."
        return 0
    fi

    local CERT_CN
    CERT_CN=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "xen-orchestra")

    # 825 days is the longest lifetime the CA/Browser Forum ever allowed for a
    # public certificate, and the ceiling most internal policies inherited. The
    # old 3650-day default outlived any reasonable key-rotation window and is
    # a standing audit finding; regenerate with --reconfigure after deleting
    # the files in SSL_CERT_DIR, or raise SSL_CERT_DAYS if you accept the risk.
    # validate_config rejects a non-numeric or zero value before this runs; the
    # fallback here only covers a caller that never loaded a config.
    local cert_days="${SSL_CERT_DAYS:-825}"
    if [[ ! "$cert_days" =~ ^[0-9]+$ ]] || (( cert_days < 1 )); then
        log_warning "SSL_CERT_DAYS='${cert_days}' is not a positive number; using 825."
        cert_days=825
    fi
    if (( cert_days > 825 )); then
        log_warning "SSL_CERT_DAYS=${cert_days} exceeds the 825-day maximum most policies"
        log_warning "allow for a TLS certificate. Continuing because you asked for it."
    fi

    run_cmd sudo openssl req -x509 -nodes -days "$cert_days" -newkey rsa:2048 \
        -keyout "${SSL_CERT_DIR}/${SSL_KEY_FILE}" \
        -out "${SSL_CERT_DIR}/${SSL_CERT_FILE}" \
        -subj "/CN=${CERT_CN}" \
        -addext "subjectAltName=DNS:${CERT_CN}"

    # Set permissions
    run_cmd sudo chmod 600 "${SSL_CERT_DIR}/${SSL_KEY_FILE}"
    run_cmd sudo chmod 644 "${SSL_CERT_DIR}/${SSL_CERT_FILE}"

    # Set ownership if service user is defined
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$SSL_CERT_DIR"
    fi

    log_success "SSL certificates generated in $SSL_CERT_DIR (valid ${cert_days} days)"
}

# Configure Xen Orchestra
configure_xo() {
    log_info "Configuring Xen Orchestra..."

    local XO_CONFIG_FILE="/etc/xo-server/config.toml"

    # Redis credential encryption stores half its key in XenStore, so it only
    # works when XO runs as a guest on a XenServer/XCP-ng host.
    if [[ "$ENCRYPT_REDIS_CREDENTIALS" == "true" ]]; then
        local VIRT_TYPE
        VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "unknown")
        if [[ "$VIRT_TYPE" != "xen" ]]; then
            log_warning "ENCRYPT_REDIS_CREDENTIALS=true but this host does not appear to be"
            log_warning "  a XenServer/XCP-ng guest (detected virtualization: ${VIRT_TYPE})."
            log_warning "  xo-server will fail to start credential encryption without XenStore."
            log_warning "  Set ENCRYPT_REDIS_CREDENTIALS=false unless XO is an XCP-ng VM."
        else
            # Being a Xen guest is necessary but not sufficient: the guest
            # utilities that expose XenStore to userspace must also be present,
            # or xo-server cannot read/write its key half. A Xen guest without
            # them passes the virt check above and then fails at startup, so
            # check for the tools rather than just the hypervisor.
            local missing_xenstore_tools=()
            local tool
            for tool in xenstore-read xenstore-write; do
                command -v "$tool" >/dev/null 2>&1 || missing_xenstore_tools+=("$tool")
            done
            if [[ ${#missing_xenstore_tools[@]} -gt 0 ]]; then
                log_warning "ENCRYPT_REDIS_CREDENTIALS=true but the XenStore guest tools are"
                log_warning "  missing: ${missing_xenstore_tools[*]}"
                log_warning "  Install the Xen guest utilities (xe-guest-utilities on XCP-ng,"
                log_warning "  or the distro's xen-guest-utilities / xen-utils package) before"
                log_warning "  enabling encryption — without them xo-server cannot store its"
                log_warning "  half of the encryption key and credential encryption will fail."
            fi

            if [[ -n "$SERVICE_USER" && "$SERVICE_USER" != "root" ]]; then
                # On a Xen guest the xenbus device is root-only by default, so a
                # non-root xo-server cannot reach XenStore. configure_xenstore_access()
                # grants the service user access (group + udev rule) so encryption works
                # without running the whole service as root. Just note it here.
                log_info "Non-root SERVICE_USER with encryption enabled — will grant"
                log_info "  ${SERVICE_USER} XenStore access (group 'xenstore' + udev rule)."
            fi
        fi
    fi

    # Create config directory
    run_cmd sudo mkdir -p /etc/xo-server

    # Create mounts directory with proper permissions
    # Note: /run/xo-server is tmpfs and will be recreated by systemd on boot
    run_cmd sudo mkdir -p /run/xo-server/mounts
    run_cmd sudo chmod 755 /run/xo-server/mounts
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        # Only chown the directories themselves — do NOT recurse into /run/xo-server/mounts
        # since active NFS/CIFS mount points live there and chown -R would fail on them
        run_cmd sudo chown "$SERVICE_USER:$SERVICE_USER" /run/xo-server
        run_cmd sudo chown "$SERVICE_USER:$SERVICE_USER" /run/xo-server/mounts
        run_cmd sudo chmod 755 /run/xo-server/mounts
    fi

    # Create configuration file
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Would write $XO_CONFIG_FILE"
    else
    sudo tee "$XO_CONFIG_FILE" > /dev/null << EOF
# Xen Orchestra Server Configuration
# Generated by install script

# Embedded HTTP server settings
[http]
$(if [[ -n "$PUBLIC_URL" ]]; then
echo "# Public URL advertised to external entities (e.g. XO Lite)"
echo "publicUrl = '$PUBLIC_URL'"
else
echo "# Public URL advertised to external entities (e.g. XO Lite). Set this if"
echo "# the host IP is not reachable as-is (reverse proxy, domain name, etc.)."
echo "#publicUrl = 'https://xo.example.com'"
fi)
$(if [[ "$REDIRECT_TO_HTTPS" == "true" ]]; then
echo "# Redirect all HTTP traffic to HTTPS"
echo "redirectToHttps = true"
fi)
$(if [[ "$REVERSE_PROXY_TRUST" != "false" ]]; then
if [[ "$REVERSE_PROXY_TRUST" == "true" ]]; then
  echo "# Trust X-Forwarded-* headers from any reverse proxy"
  echo "useForwardedHeaders = true"
else
  echo "# Trust X-Forwarded-* headers only from these proxy IP addresses"
  echo "useForwardedHeaders = ["
  for ip in $REVERSE_PROXY_TRUST; do
    echo "  '$ip',"
  done
  echo "]"
fi
fi)
# HTTP listener
[[http.listen]]
hostname = '${BIND_ADDRESS}'
port = ${HTTP_PORT}

# HTTPS listener
[[http.listen]]
hostname = '${BIND_ADDRESS}'
port = ${HTTPS_PORT}
cert = "${SSL_CERT_DIR}/${SSL_CERT_FILE}"
key = "${SSL_CERT_DIR}/${SSL_KEY_FILE}"

[redis]
$(if [[ -n "$REDIS_URI" ]]; then
echo "# Redis connection"
echo "uri = '$REDIS_URI'"
elif [[ -n "$REDIS_SOCKET" ]]; then
echo "# Redis connection via Unix socket"
echo "socket = '$REDIS_SOCKET'"
fi)
$(if [[ "$ENCRYPT_REDIS_CREDENTIALS" == "true" ]]; then
echo "# Encrypt credentials stored in Redis at rest (AES-256-GCM)."
echo "# NOTE: requires XO to run as a VM on a XenServer/XCP-ng host with"
echo "# xenstore-read/xenstore-write access — it does NOT work on bare metal"
echo "# or non-XCP-ng hypervisors. Set ENCRYPT_REDIS_CREDENTIALS=false to disable."
echo "#"
echo "# WARNING: the encryption key is split between XenStore"
echo "# (vm-data/xo-encryption-key) and /var/lib/xo-server/data/xo-encryption-key."
echo "# If either half is lost while this is enabled, DO NOT restart xo-server:"
echo "# it will regenerate both halves and the existing records become"
echo "# permanently undecryptable. Keep a passphrase-protected XO config export"
echo "# off this VM. Ref: https://docs.xen-orchestra.com/credential-encryption"
echo "encryptCredentialDatabase = true"
fi)

[remoteOptions]
mountsDir = '/run/xo-server/mounts'
useSudo = true
EOF
    fi # end DRY_RUN check

    # Set ownership if service user is defined
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" /etc/xo-server
    fi

    # Create VDDK library directory expected by xo-server for VMware V2V import
    # XO extracts the VDDK tar.gz here when uploaded via the UI
    run_cmd sudo mkdir -p /usr/local/lib/vddk
    run_cmd sudo chmod 755 /usr/local/lib/vddk

    log_success "Configuration written to $XO_CONFIG_FILE"
}

# Create systemd service
create_systemd_service() {
    log_info "Creating systemd service..."

    local NODE_PATH
    NODE_PATH=$(command -v node) || NODE_PATH=""
    local EXEC_USER="${SERVICE_USER:-root}"
    local XO_SERVER_PATH="${INSTALL_DIR}/packages/xo-server/dist/cli.mjs"
    local DEBUG_ENV=""

    if [[ "$DEBUG_MODE" == "true" ]]; then
        DEBUG_ENV="DEBUG=xo:main"
    fi

    # Capability hardening is only emitted for a non-root SERVICE_USER. As root,
    # CapabilityBoundingSet acts as a *ceiling* and would strip caps that root
    # normally holds (CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, ...), breaking
    # features that shell out to apt-get such as the VMware/ESXi import nbd build.
    local CAP_BLOCK=""
    if [[ "$EXEC_USER" != "root" ]]; then
        CAP_BLOCK=$(cat << 'CAPEOF'

# Allow binding to privileged ports (80/443)
AmbientCapabilities=CAP_NET_BIND_SERVICE
# Bounding set: ceiling for all processes in this service tree.
# CAP_NET_BIND_SERVICE: bind to ports 80/443
# CAP_SETUID/CAP_SETGID/CAP_AUDIT_WRITE: required for sudo to function
# CAP_SYS_ADMIN: required for mount syscall (NFS/CIFS remotes)
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SYS_ADMIN CAP_AUDIT_WRITE
CAPEOF
)
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Would write /etc/systemd/system/xo-server.service"
    else
    sudo tee /etc/systemd/system/xo-server.service > /dev/null << EOF
[Unit]
Description=Xen Orchestra Server
After=network-online.target redis.service valkey.service
Wants=network-online.target

[Service]
Type=simple
User=${EXEC_USER}
$(if [[ -n "$DEBUG_ENV" ]]; then echo "Environment=\"${DEBUG_ENV}\""; fi)
Environment="NODE_ENV=production"
WorkingDirectory=${INSTALL_DIR}/packages/xo-server
ExecStartPre=/bin/mkdir -p /run/xo-server/mounts
ExecStartPre=/bin/chmod 755 /run/xo-server/mounts
ExecStart=${NODE_PATH} ${XO_SERVER_PATH}
Restart=always
RestartSec=10
SyslogIdentifier=xo-server

# Runtime directory
RuntimeDirectory=xo-server
RuntimeDirectoryMode=0755

# Resource limits: set high enough that pam_limits won't need CAP_SYS_RESOURCE
# to raise them when sudo is invoked for NFS/CIFS mount operations
LimitNOFILE=1048576
LimitMEMLOCK=infinity
${CAP_BLOCK}

[Install]
WantedBy=multi-user.target
EOF
    fi # end DRY_RUN check

    # Create data directory
    run_cmd sudo mkdir -p /var/lib/xo-server
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" /var/lib/xo-server
        run_cmd sudo chmod 750 /var/lib/xo-server
    fi

    # Reload systemd and enable service
    run_cmd sudo systemctl daemon-reload
    run_cmd sudo systemctl enable xo-server

    log_success "Systemd service created and enabled"
}

# Configure sudo for non-root user
# Per official docs: https://docs.xen-orchestra.com/install-from-sources
# Only mount, umount, and findmnt are required for NFS/CIFS remote operations
configure_sudo() {
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        log_info "Configuring sudo for ${SERVICE_USER} (mount/umount/findmnt)..."

        local SUDOERS_FILE="/etc/sudoers.d/xo-server-${SERVICE_USER}"

        if [[ "$DRY_RUN" == "true" ]]; then
            echo "[DRY-RUN] Would write $SUDOERS_FILE"
        else
        sudo tee "$SUDOERS_FILE" > /dev/null << EOF
# Allow ${SERVICE_USER} to mount/unmount for XO remote storage operations
# Ref: https://docs.xen-orchestra.com/install-from-sources
${SERVICE_USER} ALL=(root) NOPASSWD: /bin/mount, /usr/bin/mount, /bin/umount, /usr/bin/umount, /bin/findmnt, /usr/bin/findmnt
EOF
        fi # end DRY_RUN check

        run_cmd sudo chmod 440 "$SUDOERS_FILE"

        log_success "Sudo configured for ${SERVICE_USER} (mount, umount, findmnt)"
    fi
}

# Grant a non-root service user access to XenStore for credential encryption.
#
# ENCRYPT_REDIS_CREDENTIALS=true makes xo-server keep half of its encryption key
# in XenStore. The guest reaches XenStore through the xenbus device, which is
# owned by root and mode 0600 by default, so a non-root xo-server cannot read or
# write it — credential encryption then fails (xo-server enters degraded mode and
# logins are rejected). XO's docs expect the xo-server process to reach XenStore
# but do not cover this OS-level permission, so we bridge that gap with least
# privilege — a dedicated 'xenstore' group plus a udev rule — rather than running
# the whole service as root. (Set SERVICE_USER=root instead if you prefer that.)
#
# Only relevant on a Xen guest with a non-root user and encryption enabled.
configure_xenstore_access() {
    [[ -n "$SERVICE_USER" && "$SERVICE_USER" != "root" ]] || return 0
    [[ "$ENCRYPT_REDIS_CREDENTIALS" == "true" ]] || return 0

    local VIRT_TYPE
    VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "unknown")
    if [[ "$VIRT_TYPE" != "xen" ]]; then
        # Not a Xen guest: encryption cannot work here regardless of user.
        # configure_xo() already warns about this, so there is nothing to grant.
        return 0
    fi

    log_info "Granting ${SERVICE_USER} XenStore access for credential encryption..."

    local UDEV_RULE="/etc/udev/rules.d/40-xen-xenbus-xo.rules"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Would create group 'xenstore', add ${SERVICE_USER}, write $UDEV_RULE, and chown /var/lib/xo-server"
    else
        # Dedicated group so the service user gets xenbus access without root.
        run_cmd sudo groupadd -f xenstore
        run_cmd sudo usermod -aG xenstore "$SERVICE_USER"

        # udev rule: hand the xenbus device node to the 'xenstore' group (rw).
        # This persists the permission across reboots / device re-creation.
        sudo tee "$UDEV_RULE" > /dev/null << 'EOF'
# Allow members of the 'xenstore' group to access the Xen xenbus device so a
# non-root xo-server can read/write XenStore for credential encryption.
# Installed by install-xen-orchestra.sh when SERVICE_USER is non-root and
# ENCRYPT_REDIS_CREDENTIALS=true.
# Ref: https://docs.xen-orchestra.com/credential-encryption
#
# The xenbus device (/dev/xen/xenbus) is a 'misc' char device whose kernel
# sysname is 'xen!xenbus' (udev encodes the '/' in xen/xenbus as '!'), verified
# via: udevadm info --name=/dev/xen/xenbus -q all
SUBSYSTEM=="misc", KERNEL=="xen!xenbus", GROUP="xenstore", MODE="0660"
EOF
        run_cmd sudo chmod 644 "$UDEV_RULE"
        # Reload/trigger are best-effort: they re-apply the rule to the live
        # device, but the explicit chgrp/chmod below is what guarantees access
        # this session. Don't let a udev quirk abort the install (set -e).
        run_cmd sudo udevadm control --reload || true
        run_cmd sudo udevadm trigger --subsystem-match=misc || true

        # Apply to the currently-present device immediately so encryption works
        # this session without a reboot (the udev rule above covers reboots, and
        # this does not depend on the udev match being exact for the live node).
        if [[ -e /dev/xen/xenbus ]]; then
            run_cmd sudo chgrp xenstore /dev/xen/xenbus
            run_cmd sudo chmod 0660 /dev/xen/xenbus
        fi

        # The other half of the key lives on disk; per official docs this path
        # must be writable by the xo-server process.
        run_cmd sudo mkdir -p /var/lib/xo-server/data
        run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" /var/lib/xo-server
    fi

    log_success "XenStore access granted to ${SERVICE_USER} (group 'xenstore' + udev rule)"
    log_warning "Group membership applies on the next xo-server restart. Verify with:"
    log_warning "  sudo -u ${SERVICE_USER} xenstore-ls vm-data"
}

# Report the user the currently-installed service runs as, by reading the
# systemd unit written by the previous run. Falls back to the install
# directory's owner when the unit is absent (e.g. a partial install).
# Echoes the username, or nothing when neither source is available.
#
# Must be called before create_systemd_service rewrites the unit.
get_previous_service_user() {
    local unit="/etc/systemd/system/xo-server.service"
    local prev=""

    if [[ -f "$unit" ]]; then
        # A unit without a User= line is normal (that is what a root install
        # looks like), so grep's exit 1 must not take the script down with it:
        # under `set -e -o pipefail` the failed pipeline would abort the caller
        # before the install-directory fallback below ever runs.
        prev=$(grep -m1 '^User=' "$unit" 2>/dev/null | cut -d'=' -f2 | tr -d '[:space:]' || true)
    fi

    if [[ -z "$prev" && -d "$INSTALL_DIR" ]]; then
        prev=$(stat -c '%U' "$INSTALL_DIR" 2>/dev/null || echo "")
    fi

    echo "$prev"
}

# Remove artifacts belonging to a previous non-root SERVICE_USER after the
# config has been switched to root.
#
# Every non-root cleanup branch in update_xo/reconfigure_xo/rebuild_xo is
# guarded by [[ "$SERVICE_USER" != "root" ]], so switching to root skips them
# all and leaves the old grants in place: a sudoers file still granting
# NOPASSWD mount/umount/findmnt to an account xo-server no longer runs as, and
# a udev rule widening access to the xenbus device. Both are written by this
# script and neither means anything for root, so drop them.
#
# The account itself is reported rather than deleted — it may own unrelated
# files or be shared with something else on the host.
#
# Arguments: previous service user (may be empty; no-op if so)
cleanup_stale_service_user() {
    local prev="$1"

    # Only relevant when we are now running as root...
    [[ "${SERVICE_USER:-root}" == "root" ]] || return 0
    # ...and were previously running as somebody else.
    [[ -n "$prev" && "$prev" != "root" ]] || return 0

    local sudoers_file="/etc/sudoers.d/xo-server-${prev}"
    local udev_rule="/etc/udev/rules.d/40-xen-xenbus-xo.rules"
    local cleaned=false

    if [[ -f "$sudoers_file" ]]; then
        log_info "SERVICE_USER is now root — removing stale sudoers grant for '${prev}'..."
        run_cmd sudo rm -f "$sudoers_file"
        cleaned=true
    fi

    if [[ -f "$udev_rule" ]]; then
        log_info "Removing XenStore udev rule (root reaches XenStore directly)..."
        run_cmd sudo rm -f "$udev_rule"
        run_cmd sudo udevadm control --reload || true
        cleaned=true
    fi

    # The udev rule is only one third of what configure_xenstore_access granted.
    # The account is also in the 'xenstore' group, and the live device node was
    # chgrp'd to that group — dropping the rule alone leaves the old account
    # with XenStore access on this boot and on every boot until the node is
    # recreated. Revoke both.
    if id -nG "$prev" 2>/dev/null | tr ' ' '\n' | grep -qx 'xenstore'; then
        log_info "Removing '${prev}' from the 'xenstore' group..."
        run_cmd sudo gpasswd -d "$prev" xenstore >/dev/null 2>&1 || true
        cleaned=true
    fi

    if [[ -e /dev/xen/xenbus ]]; then
        local dev_group=""
        dev_group=$(stat -c '%G' /dev/xen/xenbus 2>/dev/null || echo "")
        if [[ "$dev_group" == "xenstore" ]]; then
            log_info "Restoring root-only permissions on /dev/xen/xenbus..."
            run_cmd sudo chgrp root /dev/xen/xenbus || true
            run_cmd sudo chmod 0600 /dev/xen/xenbus || true
            cleaned=true
        fi
    fi

    if [[ "$cleaned" == "true" ]]; then
        log_success "Removed leftover service-user grants for '${prev}'"
    fi

    if id "$prev" &>/dev/null; then
        log_warning "The '${prev}' account is no longer used by xo-server. It was left"
        log_warning "in place in case other files or services depend on it. Remove it"
        log_warning "manually once you are sure: sudo userdel -r ${prev}"
    fi

    return 0
}

# Open the Xen Orchestra web ports in the host firewall.
# Fedora and RHEL-family distros (RHEL/CentOS/Rocky/Alma) enable firewalld by
# default and block inbound HTTP/HTTPS; Debian/Ubuntu ship no active firewall.
# This is a no-op unless firewalld is installed AND running, so it is safe to
# call on every distro. Uses the standard firewalld workflow (a permanent rule
# for each configured port, then a reload). Re-adding an existing port is
# idempotent, so this is also safe on --reconfigure/--rebuild.
configure_firewall() {
    if ! command -v firewall-cmd >/dev/null 2>&1 || ! firewall-cmd --state >/dev/null 2>&1; then
        # No firewalld (Debian/Ubuntu) or it is not running — nothing to open.
        return 0
    fi

    log_info "Opening firewall ports ${HTTP_PORT}/tcp and ${HTTPS_PORT}/tcp (firewalld)..."
    run_cmd sudo firewall-cmd --permanent --add-port="${HTTP_PORT}/tcp"
    run_cmd sudo firewall-cmd --permanent --add-port="${HTTPS_PORT}/tcp"
    run_cmd sudo firewall-cmd --reload

    log_success "Firewall configured (firewalld): ${HTTP_PORT}/tcp and ${HTTPS_PORT}/tcp open"
}

# Run git in the install directory as the directory owner
# This avoids git's dubious ownership check regardless of SERVICE_USER
install_dir_git() {
    local DIR_OWNER
    DIR_OWNER=$(stat -c '%U' "$INSTALL_DIR" 2>/dev/null)
    sudo -u "$DIR_OWNER" git -C "$INSTALL_DIR" "$@"
}

# Get current installed commit
get_installed_commit() {
    if sudo test -d "$INSTALL_DIR/.git" 2>/dev/null; then
        install_dir_git rev-parse HEAD 2>/dev/null
    else
        echo ""
    fi
}

# Get remote commit
get_remote_commit() {
    git ls-remote https://github.com/vatesfr/xen-orchestra refs/heads/"$GIT_BRANCH" 2>/dev/null | cut -f1
}

# Create backup
create_backup() {
    log_info "Creating backup of current installation..."

    run_cmd sudo mkdir -p "$BACKUP_DIR"

    local TIMESTAMP
    TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
    local BACKUP_NAME="xo-backup-${TIMESTAMP}"
    local BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

    # Create backup.  node_modules is dropped to save space; yarn reinstalls it
    # on the next build.  Turbo's cache (.turbo/cache, ~15MB) is deliberately
    # kept: without it the first update after a restore would be a cold full
    # rebuild of all ~25 packages, which costs far more than the space saved.
    run_cmd sudo cp -r "$INSTALL_DIR" "$BACKUP_PATH"
    run_cmd sudo rm -rf "${BACKUP_PATH}/node_modules"

    log_success "Backup created: $BACKUP_PATH"

    # This backup copies $INSTALL_DIR only. Neither half of the credential
    # encryption key lives there (one half is in XenStore, the other in
    # /var/lib/xo-server/data), so it is not a recovery artifact for an
    # encrypted Redis database. An in-place restore is unaffected — restore_xo()
    # never touches /var/lib/xo-server — but rebuilding the VM from this backup
    # alone would leave the records permanently undecryptable. Upstream's
    # recovery path for an encrypted install is the passphrase-protected
    # config export, so point at it rather than implying coverage we lack.
    if [[ "${ENCRYPT_REDIS_CREDENTIALS:-false}" == "true" ]]; then
        log_warning "Credential encryption is enabled. This backup does NOT contain"
        log_warning "  either half of the encryption key, so it cannot by itself restore"
        log_warning "  an encrypted Redis database onto a rebuilt VM."
        log_warning "  Also export the XO config from the web UI (Settings -> Config) —"
        log_warning "  it prompts for a passphrase and is the portable copy of the data."
        log_warning "  Ref: https://docs.xen-orchestra.com/credential-encryption"
    fi

    # Purge old backups, keep only the latest BACKUP_KEEP
    log_info "Cleaning old backups (keeping ${BACKUP_KEEP})..."
    local ALL_BACKUPS=()
    while IFS= read -r -d '' dir; do
        ALL_BACKUPS+=("$dir")
    done < <(find "$BACKUP_DIR" -maxdepth 1 -name "xo-backup-*" -type d -print0 2>/dev/null | sort -zr)

    local TOTAL_BACKUPS=${#ALL_BACKUPS[@]}
    if [[ $TOTAL_BACKUPS -gt $BACKUP_KEEP ]]; then
        local TO_DELETE=$(( TOTAL_BACKUPS - BACKUP_KEEP ))
        log_info "Removing ${TO_DELETE} old backup(s)..."
        for (( idx=BACKUP_KEEP; idx<TOTAL_BACKUPS; idx++ )); do
            log_info "Removing old backup: $(basename "${ALL_BACKUPS[$idx]}")"
            run_cmd sudo rm -rf "${ALL_BACKUPS[$idx]}"
        done
    fi

    log_success "Old backups cleaned"
}

# Restore Xen Orchestra from a backup
restore_xo() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        log_error "Backup directory not found: $BACKUP_DIR"
        exit 1
    fi

    # Build sorted (newest first) list of backups
    local BACKUPS=()
    while IFS= read -r -d '' dir; do
        BACKUPS+=("$dir")
    done < <(find "$BACKUP_DIR" -maxdepth 1 -name "xo-backup-*" -type d -print0 2>/dev/null | sort -zr)

    if [[ ${#BACKUPS[@]} -eq 0 ]]; then
        log_error "No backups found in $BACKUP_DIR"
        exit 1
    fi

    echo ""
    echo "=============================================="
    echo "  Available Backups"
    echo "=============================================="
    echo ""

    local TOTAL_TO_LIST=${#BACKUPS[@]}
    local i=1
    for BACKUP in "${BACKUPS[@]}"; do
        local BACKUP_NAME
        BACKUP_NAME=$(basename "$BACKUP")
        # Read commit hash from backup's git repo, running as the directory owner
        local BACKUP_COMMIT=""
        if [[ -d "$BACKUP/.git" ]]; then
            local BACKUP_OWNER
            BACKUP_OWNER=$(stat -c '%U' "$BACKUP" 2>/dev/null)
            BACKUP_COMMIT=$(sudo -u "$BACKUP_OWNER" git -C "$BACKUP" rev-parse HEAD 2>/dev/null | cut -c1-12 || true)
        fi
        # Parse timestamp from name: xo-backup-YYYYMMDD_HHMMSS
        # Format using local system timezone in 12-hour time
        local TS="${BACKUP_NAME#xo-backup-}"
        local RAW_DT="${TS:0:4}-${TS:4:2}-${TS:6:2} ${TS:9:2}:${TS:11:2}:${TS:13:2} UTC"
        local DATETIME
        DATETIME=$(date -d "$RAW_DT" +"%I:%M:%S %p %Z" 2>/dev/null || echo "${RAW_DT% UTC}")
        # Label newest and oldest
        local LABEL=""
        if [[ $i -eq 1 ]]; then
            LABEL=" (newest)"
        elif [[ $i -eq $TOTAL_TO_LIST ]]; then
            LABEL=" (oldest)"
        fi
        if [[ -n "$BACKUP_COMMIT" ]]; then
            printf "  [%d] %s  (%s)  commit: %s%s\n" "$i" "$BACKUP_NAME" "$DATETIME" "$BACKUP_COMMIT" "$LABEL"
        else
            printf "  [%d] %s  (%s)%s\n" "$i" "$BACKUP_NAME" "$DATETIME" "$LABEL"
        fi
        ((i++))
    done

    local TOTAL=$((i - 1))
    echo ""
    local CHOICE
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if [[ -n "$RESTORE_BACKUP_FILE" ]]; then
            CHOICE=""
            for idx in "${!BACKUPS[@]}"; do
                if [[ "$(basename "${BACKUPS[$idx]}")" == "$RESTORE_BACKUP_FILE" ]]; then
                    CHOICE=$((idx + 1))
                    break
                fi
            done
            if [[ -z "$CHOICE" ]]; then
                log_error "Backup not found: $RESTORE_BACKUP_FILE"
                exit 1
            fi
        else
            log_info "Non-interactive: auto-selecting newest backup: $(basename "${BACKUPS[0]}")"
            CHOICE=1
        fi
    else
        echo -n "Enter the number of the backup to restore [1-${TOTAL}], or 'q' to quit: "
        read -t 300 -r CHOICE || { log_error "Input timeout"; exit 1; }
        if [[ "$CHOICE" == "q" ]] || [[ "$CHOICE" == "Q" ]]; then
            log_info "Restore cancelled."
            exit 0
        fi
    fi

    if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || [[ "$CHOICE" -lt 1 ]] || [[ "$CHOICE" -gt "$TOTAL" ]]; then
        log_error "Invalid selection: $CHOICE"
        exit 1
    fi

    local SELECTED_BACKUP="${BACKUPS[$((CHOICE - 1))]}"
    local SELECTED_NAME
    SELECTED_NAME=$(basename "$SELECTED_BACKUP")

    echo ""
    log_warning "You are about to restore: $SELECTED_NAME"
    log_warning "This will replace the current installation at $INSTALL_DIR"
    confirm_or_skip "Restore $SELECTED_NAME? This will replace $INSTALL_DIR" || { log_info "Restore cancelled."; exit 0; }

    # Stop the service
    log_info "Stopping xo-server service..."
    run_cmd sudo systemctl stop xo-server || true

    # Remove current installation
    log_info "Removing current installation..."
    run_cmd sudo rm -rf "$INSTALL_DIR"

    # Copy backup into place
    log_info "Restoring from backup: $SELECTED_NAME"
    run_cmd sudo cp -r "$SELECTED_BACKUP" "$INSTALL_DIR"

    # Fix ownership to match current SERVICE_USER
    local DIR_OWNER
    DIR_OWNER=$(stat -c '%U' "$INSTALL_DIR" 2>/dev/null)
    if [[ "$SERVICE_USER" != "$DIR_OWNER" ]]; then
        log_info "Updating directory ownership from ${DIR_OWNER} to ${SERVICE_USER}..."
        if [[ "$SERVICE_USER" == "root" ]]; then
            run_cmd sudo chown -R root:root "$INSTALL_DIR"
        else
            run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
            run_cmd sudo chmod -R o-rwx "$INSTALL_DIR"
        fi
    fi

    # Rebuild — node_modules are excluded from backups
    log_info "Rebuilding Xen Orchestra (node_modules were excluded from backup)..."
    build_xo

    # Regenerate the systemd service file to pick up any script changes
    create_systemd_service

    # Start the service
    log_info "Starting xo-server service..."
    run_cmd sudo systemctl start xo-server
    wait_for_xo_ready

    local RESTORED_COMMIT
    RESTORED_COMMIT=$(get_installed_commit)

    echo ""
    echo "=============================================="
    log_success "Restore completed successfully!"
    echo "=============================================="
    log_info "Restored commit: ${RESTORED_COMMIT:0:12}"

    if systemctl is-active --quiet xo-server; then
        log_success "xo-server is running"
    else
        log_warning "xo-server may have failed to start. Check: sudo systemctl status xo-server"
    fi
    echo ""
}

# Check for active Xen Orchestra tasks before updating.
# Authenticates via token, config credentials, or interactive prompt, then
# queries the XO REST API for pending tasks and aborts if any are found.
# Auth priority: 1) XO_TASK_CHECK_TOKEN  2) XO_TASK_CHECK_USER/PASS  3) interactive prompt
# Passwords are never logged, cached, or written to disk.
#
# NOTE: XO_TASK_CHECK_TOKEN must be a persistent API token created in XO's web
# UI (open your user menu → Tokens; the exact menu location varies by XO
# version) or via the REST API with a "description" field in the request body.
# The token is sent to the REST API via the authenticationToken cookie.
# During updates flush_redis_tokens() preserves tokens that have a non-empty
# description and deletes tokens without one (browser sessions). A token
# created without a description will be wiped on the next update.
#
# Orphan filter: tasks whose start time predates xo-server's process start
# are treated as stale DB records (e.g. left over after restoring an XO
# config backup onto a new VM) and excluded from the active-task count.
# A genuine running task cannot have started before the process running it.
# If xo-server's start time can't be determined, the filter is a no-op
# and all pending tasks are counted (fail-safe to original behavior).
check_active_xo_tasks() {
    log_info "Checking for active Xen Orchestra tasks before updating..."
    printf '\n'

    local xo_user="" xo_pass="" xo_token="" auth_method="" auth_label=""
    local base_url proto port
    local http_code="" task_response="" task_count=0
    local connected=false

    # Determine authentication method
    if [[ -n "${XO_TASK_CHECK_TOKEN:-}" ]]; then
        # Priority 1: Auth token from config
        auth_method="token"
        xo_token="$XO_TASK_CHECK_TOKEN"
        auth_label="authentication token"
        log_info "Using authentication token from xo-config.cfg..."
    elif [[ -n "${XO_TASK_CHECK_USER:-}" && -n "${XO_TASK_CHECK_PASS:-}" ]]; then
        # Priority 2: Credentials from config
        auth_method="credentials"
        xo_user="$XO_TASK_CHECK_USER"
        xo_pass="$XO_TASK_CHECK_PASS"
        auth_label="'${xo_user}' (from xo-config.cfg)"
        log_info "Using credentials from xo-config.cfg..."
    else
        # Priority 3: Interactive prompt
        if [[ "$NON_INTERACTIVE" == "true" ]]; then
            log_warning "Non-interactive mode: no XO credentials configured. Skipping task check."
            return 0
        fi
        auth_method="interactive"
        log_info "Enter your Xen Orchestra web UI credentials to check for running tasks."
        log_info "(Press Enter on username to skip and proceed with the update.)"
        printf '\n'

        read -rp "XO Username: " xo_user < /dev/tty
        if [[ -z "$xo_user" ]]; then
            log_warning "Task check skipped. Ensure no tasks are running before proceeding."
            return 0
        fi

        # Read password silently — never logged, cached, or written to disk
        read -rsp "XO Password: " xo_pass < /dev/tty
        printf '\n'
        if [[ -z "$xo_pass" ]]; then
            log_warning "No password provided. Task check skipped."
            return 0
        fi
        auth_label="'${xo_user}'"
    fi

    # Temp file for API response body (task data only — not sensitive)
    local resp_file
    resp_file=$(mktemp /tmp/xo-resp-XXXXXX)

    # Retry loop: on 401 from a token/config source, offer to re-enter credentials
    local auth_attempts=0
    local max_auth_attempts=3
    while [[ $auth_attempts -lt $max_auth_attempts ]]; do
        (( auth_attempts++ )) || true

        log_info "Querying active tasks as ${auth_label}..."

        # Try HTTPS first (XO default), fall back to HTTP
        http_code=""
        connected=false
        for proto in https http; do
            if [[ "$proto" == "https" ]]; then
                port="$HTTPS_PORT"
            else
                port="$HTTP_PORT"
            fi
            base_url="${proto}://localhost:${port}"

            # Build curl options
            # Note: -k (skip TLS verify) is acceptable — loopback only, self-signed cert
            local curl_opts=(-s --max-time 15
                --output "$resp_file"
                --write-out "%{http_code}")
            if [[ "$proto" == "https" ]]; then
                curl_opts+=(-k)
            fi

            if [[ "$auth_method" == "token" ]]; then
                # Token auth — passed via cookie header
                http_code=$(curl "${curl_opts[@]}" \
                    -b "authenticationToken=${xo_token}" \
                    "${base_url}/rest/v0/tasks?filter=status%3Apending&fields=*" \
                    2>/dev/null) || true
            else
                # Basic auth — pipe credentials via curl's -K stdin to keep password out of argv
                local esc_user esc_pass
                esc_user=$(printf '%s' "$xo_user" | sed 's/"/\\"/g')
                esc_pass=$(printf '%s' "$xo_pass" | sed 's/"/\\"/g')

                http_code=$(printf 'user = "%s:%s"\n' "$esc_user" "$esc_pass" | \
                    curl "${curl_opts[@]}" -K - \
                    "${base_url}/rest/v0/tasks?filter=status%3Apending&fields=*" \
                    2>/dev/null) || true

                # Wipe escaped credentials immediately
                esc_pass="" ; unset esc_pass
            fi

            if [[ "$http_code" == "200" ]]; then
                task_response=$(< "$resp_file")
                connected=true
                break
            fi
        done

        # Success — exit the retry loop
        if [[ "$connected" == "true" ]]; then
            break
        fi

        # On 401: token may be expired or credentials wrong — offer a retry
        if [[ "${http_code}" == "401" ]]; then
            # Clear expired/invalid credentials from memory
            xo_pass="" ; unset xo_pass
            xo_token="" ; unset xo_token

            if [[ "$NON_INTERACTIVE" == "true" ]]; then
                log_warning "Authentication failed for ${auth_label} (token may be expired). Task check skipped."
                rm -f "$resp_file"
                return 0
            fi

            log_warning "Authentication failed for ${auth_label} — the token or credentials may be expired or invalid."
            printf '\n'

            if [[ $auth_attempts -ge $max_auth_attempts ]]; then
                log_warning "Too many failed authentication attempts. Task check skipped."
                rm -f "$resp_file"
                return 0
            fi

            # Offer re-entry: new token or username/password
            printf "  [1] Enter a new authentication token\n"
            printf "  [2] Enter username and password\n"
            printf "  [s] Skip the task check and proceed with the update\n"
            printf '\n'
            local retry_choice
            read -rp "Choice [1/2/s]: " retry_choice < /dev/tty

            case "$retry_choice" in
                1)
                    read -rsp "New authentication token: " xo_token < /dev/tty
                    printf '\n'
                    if [[ -z "$xo_token" ]]; then
                        log_warning "No token entered. Task check skipped."
                        rm -f "$resp_file"
                        return 0
                    fi
                    auth_method="token"
                    auth_label="new authentication token"
                    ;;
                2)
                    read -rp "XO Username: " xo_user < /dev/tty
                    if [[ -z "$xo_user" ]]; then
                        log_warning "No username entered. Task check skipped."
                        rm -f "$resp_file"
                        return 0
                    fi
                    read -rsp "XO Password: " xo_pass < /dev/tty
                    printf '\n'
                    if [[ -z "$xo_pass" ]]; then
                        log_warning "No password provided. Task check skipped."
                        rm -f "$resp_file"
                        return 0
                    fi
                    auth_method="credentials"
                    auth_label="'${xo_user}'"
                    ;;
                *)
                    log_warning "Task check skipped. Ensure no tasks are running before proceeding."
                    rm -f "$resp_file"
                    return 0
                    ;;
            esac
        else
            # Non-auth failure (network, etc.) — no point retrying
            break
        fi
    done

    # Clear sensitive values from memory — no longer needed
    xo_pass="" ; unset xo_pass
    xo_token="" ; unset xo_token
    rm -f "$resp_file"

    if [[ "$connected" != "true" ]]; then
        if [[ "${http_code}" == "401" ]]; then
            log_warning "Authentication failed for ${auth_label}. Task check skipped."
        else
            log_warning "Could not reach XO API (HTTP ${http_code:-unreachable}). Task check skipped."
        fi
        return 0
    fi

    # Determine xo-server's process start time (epoch ms) for orphan filtering.
    # Tasks predating xo-server can't be live runs — they're stale DB records,
    # commonly left over after restoring an XO config backup to a new VM.
    # Best-effort: if any step fails, xo_start_ms stays empty and the filter
    # below becomes a no-op (fail-safe to original count-everything behavior).
    local xo_pid="" xo_lstart="" xo_start_s="" xo_start_ms="" total_pending=0
    xo_pid=$(systemctl show -p MainPID --value xo-server 2>/dev/null) || xo_pid=""
    if [[ -n "$xo_pid" && "$xo_pid" != "0" ]]; then
        xo_lstart=$(ps -o lstart= -p "$xo_pid" 2>/dev/null) || xo_lstart=""
        if [[ -n "$xo_lstart" ]]; then
            # GNU date -d parses the lstart string; non-GNU date will fail and we fall back
            xo_start_s=$(date -d "$xo_lstart" +%s 2>/dev/null) || xo_start_s=""
            if [[ "$xo_start_s" =~ ^[0-9]+$ ]]; then
                xo_start_ms=$((xo_start_s * 1000))
            fi
        fi
    fi

    # Parse task count — jq preferred, node.js fallback (guaranteed on any XO install)
    # Filter: exclude "XO user authentication" tasks, and orphans (start < xo_start_ms).
    # cutoff=0 disables the orphan filter (fail-safe when xo_start_ms unknown).
    if command -v jq &>/dev/null; then
        total_pending=$(printf '%s' "$task_response" \
            | jq '[.[] | select((.properties.name // "") != "XO user authentication")] | length' \
            2>/dev/null) || total_pending=0
        task_count=$(printf '%s' "$task_response" \
            | jq --argjson cutoff "${xo_start_ms:-0}" '
                [.[]
                 | select((.properties.name // "") != "XO user authentication")
                 | select($cutoff == 0 or (.start // 0) >= $cutoff)
                ] | length' \
            2>/dev/null) || task_count=0
    else
        # shellcheck disable=SC2016
        local node_counts
        node_counts=$(printf '%s' "$task_response" | XO_CUTOFF="${xo_start_ms:-0}" node -e '
            let d = "";
            process.stdin.on("data", c => d += c);
            process.stdin.on("end", () => {
                try {
                    const cutoff = parseInt(process.env.XO_CUTOFF || "0", 10) || 0;
                    const a = JSON.parse(d);
                    const named = Array.isArray(a)
                        ? a.filter(t => (t.properties && t.properties.name) !== "XO user authentication")
                        : [];
                    const live = named.filter(t => cutoff === 0 || (t.start || 0) >= cutoff);
                    process.stdout.write(named.length + " " + live.length);
                } catch (e) { process.stdout.write("0 0"); }
            });
        ' 2>/dev/null) || node_counts="0 0"
        total_pending=${node_counts% *}
        task_count=${node_counts#* }
    fi

    # Ensure counts are valid integers before numeric comparison
    if ! [[ "$task_count" =~ ^[0-9]+$ ]]; then
        task_count=0
    fi
    if ! [[ "$total_pending" =~ ^[0-9]+$ ]]; then
        total_pending=0
    fi

    # Inform the user when orphans were filtered out (post-restore scenario)
    if [[ -n "$xo_start_ms" && "$total_pending" -gt "$task_count" ]]; then
        local filtered=$((total_pending - task_count))
        log_info "Filtered ${filtered} stale task(s) predating xo-server start (likely orphans from a config restore)."
    fi

    if [[ "$task_count" -gt 0 ]]; then
        log_error "Update aborted: ${task_count} active task(s) found in Xen Orchestra."
        log_error "Task check performed by: ${auth_label}"
        log_error "Active tasks:"

        # List task names — node fallback if jq not available.
        # Same cutoff filter as the count above, so orphans aren't named.
        if command -v jq &>/dev/null; then
            while IFS= read -r task_line; do
                printf '%b\n' "${RED}[ERROR]${NC}   - ${task_line}"
            done < <(printf '%s' "$task_response" \
                | jq -r --argjson cutoff "${xo_start_ms:-0}" '
                    [.[]
                     | select((.properties.name // "") != "XO user authentication")
                     | select($cutoff == 0 or (.start // 0) >= $cutoff)
                    ] | .[] | (.properties.name // .id // "unknown task")' \
                2>/dev/null || true)
        else
            # shellcheck disable=SC2016
            printf '%s' "$task_response" | XO_CUTOFF="${xo_start_ms:-0}" node -e '
                let d = "";
                process.stdin.on("data", c => d += c);
                process.stdin.on("end", () => {
                    try {
                        const cutoff = parseInt(process.env.XO_CUTOFF || "0", 10) || 0;
                        const tasks = JSON.parse(d);
                        if (Array.isArray(tasks)) {
                            tasks
                                .filter(t => (t.properties && t.properties.name) !== "XO user authentication")
                                .filter(t => cutoff === 0 || (t.start || 0) >= cutoff)
                                .forEach(t => {
                                    const name = (t.properties && t.properties.name)
                                        || t.id || "unknown task";
                                    process.stdout.write("         - " + name + "\n");
                                });
                        }
                    } catch (e) {}
                });
            ' 2>/dev/null || true
        fi

        printf '\n'
        log_info "Wait for all tasks to complete, then re-run the update."
        exit 1
    fi

    log_success "No active tasks found. Proceeding with update..."
    log_info "Task check performed by: ${auth_label}"
}

# Update Xen Orchestra
# Warn when the running Node.js version diverges from NODE_VERSION in config.
# Called inside update_xo before install_nodejs so the operator gets a clear
# heads-up that a runtime change is coming (install_nodejs handles the actual
# upgrade/downgrade).
detect_nodejs_drift() {
    local RUNNING_FULL
    RUNNING_FULL=$(node -v 2>/dev/null | sed 's/^v//')
    if [[ -z "$RUNNING_FULL" ]]; then
        log_warning "Could not determine running Node.js version — skipping drift check"
        return 0
    fi

    local RUNNING_MAJOR="${RUNNING_FULL%%.*}"
    local CONFIG_MAJOR="${NODE_VERSION%%.*}"

    if ! version_satisfies "$RUNNING_FULL" "$NODE_VERSION"; then
        log_warning "Node.js version drift detected:"
        log_warning "  Running : v${RUNNING_FULL}  (major: ${RUNNING_MAJOR})"
        log_warning "  Config  : ${NODE_VERSION}  (major: ${CONFIG_MAJOR})"
        log_warning "  Node.js will be updated to match NODE_VERSION=${NODE_VERSION} from xo-config.cfg"
    else
        log_info "Node.js v${RUNNING_FULL} satisfies configured version ${NODE_VERSION} — no runtime change needed"
    fi
}

update_xo() {
    log_info "Checking for updates..."

    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_error "Xen Orchestra is not installed. Run without --update first."
        exit 1
    fi

    local INSTALLED_COMMIT REMOTE_COMMIT
    # Keep failures non-fatal here so the explicit empty-value checks below emit a
    # clean message instead of letting a transient git/network error trip `set -e`.
    INSTALLED_COMMIT=$(get_installed_commit) || INSTALLED_COMMIT=""
    REMOTE_COMMIT=$(get_remote_commit) || REMOTE_COMMIT=""

    if [[ -z "$INSTALLED_COMMIT" ]]; then
        log_error "Could not determine installed commit"
        exit 1
    fi

    if [[ -z "$REMOTE_COMMIT" ]]; then
        log_error "Could not fetch remote commit"
        exit 1
    fi

    log_info "Installed commit: ${INSTALLED_COMMIT:0:12}"
    log_info "Remote commit:    ${REMOTE_COMMIT:0:12}"

    if [[ "$INSTALLED_COMMIT" == "$REMOTE_COMMIT" ]]; then
        log_success "Already up to date. No update needed."
        # No code change means no token-schema flush is warranted, but a
        # config restore can still leave orphaned tokens behind — surface
        # them so the user knows to run --flush-tokens.
        check_orphaned_tokens
        exit 0
    fi

    log_info "New version available. Proceeding with update..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would update from commit ${INSTALLED_COMMIT:0:12} to ${REMOTE_COMMIT:0:12}"
        log_info "[DRY-RUN] Would stop service, create backup, pull latest, rebuild, restart"
        return 0
    fi

    # Check for active tasks before stopping the service
    check_active_xo_tasks

    # Stop service
    log_info "Stopping xo-server service..."
    run_cmd sudo systemctl stop xo-server || true

    # Flush stale auth tokens — the new version may have a different token
    # schema and cannot deserialize tokens written by the old version
    flush_redis_tokens

    # Create backup
    create_backup

    # Update repository
    log_info "Pulling latest changes..."

    install_dir_git checkout .
    install_dir_git fetch origin
    install_dir_git checkout -B "$GIT_BRANCH" "origin/$GIT_BRANCH"

    # Ensure service user exists before any chown operations
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        if ! id "$SERVICE_USER" &>/dev/null; then
            log_info "Creating service user: $SERVICE_USER"
            run_cmd sudo useradd -r -m -s /bin/bash "$SERVICE_USER" || true
        fi
    fi

    # Record what the service ran as before, so a switch to root can clean up
    # the previous user's grants further down (create_systemd_service below
    # overwrites the unit this is read from).
    local PREV_SERVICE_USER
    PREV_SERVICE_USER=$(get_previous_service_user)

    # Fix ownership if SERVICE_USER changed since initial install
    local DIR_OWNER
    DIR_OWNER=$(stat -c '%U' "$INSTALL_DIR" 2>/dev/null)
    if [[ "$SERVICE_USER" != "$DIR_OWNER" ]]; then
        log_info "Updating directory ownership from ${DIR_OWNER} to ${SERVICE_USER}..."
        if [[ "$SERVICE_USER" == "root" ]]; then
            run_cmd sudo chown -R root:root "$INSTALL_DIR"
        else
            run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
        fi
    fi

    # Detect Node.js version drift before upgrading/downgrading
    detect_nodejs_drift

    # Ensure Node.js version matches config (upgrade/downgrade if needed)
    install_nodejs
    install_yarn

    # Rebuild, reusing the local turbo cache for any package that didn't
    # change since the last build (see build_xo's TURBO_CACHE comment).
    build_xo

    # Regenerate the systemd service file to pick up any script changes
    create_systemd_service

    # Regenerate sudoers for non-root service user (tightens legacy rules)
    configure_sudo

    # Grant XenStore access if a non-root user has credential encryption enabled
    configure_xenstore_access

    # Drop the previous user's sudoers/udev grants if SERVICE_USER became root
    cleanup_stale_service_user "$PREV_SERVICE_USER"

    # Ensure the web ports are open in firewalld (Fedora/RHEL)
    configure_firewall

    # Apply security hardening (permissions, ownership, group cleanup)
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        # Remove legacy root group membership from previous script versions
        if id -nG "$SERVICE_USER" 2>/dev/null | grep -qw root; then
            log_info "Removing ${SERVICE_USER} from root group (no longer needed)..."
            run_cmd sudo gpasswd -d "$SERVICE_USER" root 2>/dev/null || true
        fi

        # Ensure proper file permissions
        log_info "Applying security hardening..."
        run_cmd sudo chmod -R o-rwx "$INSTALL_DIR"
        run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" /etc/xo-server
        if [[ -d "$SSL_CERT_DIR" ]]; then
            run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$SSL_CERT_DIR"
        fi
        if [[ -d /var/lib/xo-server ]]; then
            run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" /var/lib/xo-server
            run_cmd sudo chmod 750 /var/lib/xo-server
        fi
    fi

    # Reload systemd daemon to pick up service changes
    run_cmd sudo systemctl daemon-reload

    # Start service
    log_info "Starting xo-server service..."
    run_cmd sudo systemctl start xo-server
    wait_for_xo_ready

    log_success "Update completed successfully!"
    log_info "New commit: $(get_installed_commit | cut -c1-12)"
}

# Rebuild Xen Orchestra from scratch on the current branch.
# Takes a backup first, then does a fresh clone + clean build while
# leaving user settings (/etc/xo-server, /var/lib/xo-server) untouched.
rebuild_xo() {
    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_error "Xen Orchestra is not installed at $INSTALL_DIR."
        log_error "Run the script without options to perform a fresh install."
        exit 1
    fi

    # Detect the currently checked-out branch
    local CURRENT_BRANCH
    CURRENT_BRANCH=$(install_dir_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "$GIT_BRANCH")

    local CURRENT_COMMIT
    CURRENT_COMMIT=$(get_installed_commit)

    echo ""
    echo "=============================================="
    echo "  Xen Orchestra Rebuild"
    echo "=============================================="
    echo ""
    log_info "Current branch:  ${CURRENT_BRANCH}"
    log_info "Current commit:  ${CURRENT_COMMIT:0:12}"
    log_info "Install dir:     ${INSTALL_DIR}"
    echo ""
    log_warning "This will:"
    log_warning "  1. Back up the current installation to ${BACKUP_DIR}"
    log_warning "  2. Remove ${INSTALL_DIR} and do a fresh clone from branch '${CURRENT_BRANCH}'"
    log_warning "  3. Perform a clean rebuild"
    log_info "Settings in /etc/xo-server and /var/lib/xo-server will NOT be changed."
    echo ""
    confirm_or_skip "Continue with rebuild?" || { log_info "Rebuild cancelled."; exit 0; }

    # Stop the service before touching anything
    log_info "Stopping xo-server service..."
    run_cmd sudo systemctl stop xo-server || true

    # Flush stale auth tokens before the fresh build takes over
    flush_redis_tokens

    # Backup current installation (node_modules excluded, same as update)
    create_backup

    # Wipe current installation directory
    log_info "Removing current installation directory..."
    run_cmd sudo rm -rf "$INSTALL_DIR"

    # Fresh clone of the same branch
    log_info "Cloning Xen Orchestra (branch: ${CURRENT_BRANCH})..."
    run_cmd sudo mkdir -p "$(dirname "$INSTALL_DIR")"
    run_cmd sudo git clone -b "$CURRENT_BRANCH" https://github.com/vatesfr/xen-orchestra "$INSTALL_DIR"

    # Ensure service user exists before any chown operations
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        if ! id "$SERVICE_USER" &>/dev/null; then
            log_info "Creating service user: $SERVICE_USER"
            run_cmd sudo useradd -r -m -s /bin/bash "$SERVICE_USER" || true
        fi
    fi

    # Restore ownership
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
        run_cmd sudo chmod -R o-rwx "$INSTALL_DIR"
    fi

    # Record what the service ran as before, so a switch to root can clean up
    # the previous user's grants further down (create_systemd_service below
    # overwrites the unit this is read from).
    local PREV_SERVICE_USER
    PREV_SERVICE_USER=$(get_previous_service_user)

    # Ensure Node.js version matches config (upgrade/downgrade if needed)
    install_nodejs
    install_yarn

    # Clean build to ensure no stale artefacts
    build_xo clean

    # Regenerate the systemd service file to pick up any script changes
    create_systemd_service

    # Drop the previous user's sudoers/udev grants if SERVICE_USER became root
    cleanup_stale_service_user "$PREV_SERVICE_USER"

    # Restart the service
    log_info "Starting xo-server service..."
    run_cmd sudo systemctl start xo-server
    wait_for_xo_ready

    local NEW_COMMIT
    NEW_COMMIT=$(get_installed_commit)

    echo ""
    echo "=============================================="
    log_success "Rebuild completed successfully!"
    echo "=============================================="
    log_info "Branch:      ${CURRENT_BRANCH}"
    log_info "New commit:  ${NEW_COMMIT:0:12}"

    log_info "Your settings in /etc/xo-server and /var/lib/xo-server are unchanged."
    echo ""
}

# Reconfigure Xen Orchestra from xo-config.cfg
# Regenerates /etc/xo-server/config.toml and systemd service
reconfigure_xo() {
    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_error "Xen Orchestra is not installed at $INSTALL_DIR."
        log_error "Run the script without options to perform a fresh install."
        exit 1
    fi

    echo ""
    echo "=============================================="
    echo "  Xen Orchestra Reconfiguration"
    echo "=============================================="
    echo ""
    log_info "This will regenerate configuration from xo-config.cfg:"
    log_warning "  - /etc/xo-server/config.toml"
    log_warning "  - /etc/systemd/system/xo-server.service"
    log_warning "  - /etc/sudoers.d/xo-server-* (if non-root service user)"
    echo ""
    log_info "Current configuration from xo-config.cfg:"
    echo "  - HTTP Port:        ${HTTP_PORT}"
    echo "  - HTTPS Port:       ${HTTPS_PORT}"
    echo "  - Bind Address:     ${BIND_ADDRESS:-0.0.0.0}"
    echo "  - Install Dir:      ${INSTALL_DIR}"
    echo "  - Service User:     ${SERVICE_USER:-root}"
    echo "  - SSL Cert Dir:     ${SSL_CERT_DIR}"
    [[ "${REDIRECT_TO_HTTPS}" == "true" ]] && echo "  - Redirect to HTTPS: Enabled"
    [[ -n "${REDIS_URI}" ]] && echo "  - Redis URI:        ${REDIS_URI}"
    [[ -n "${REDIS_SOCKET}" ]] && echo "  - Redis Socket:     ${REDIS_SOCKET}"
    [[ "${DEBUG_MODE}" == "true" ]] && echo "  - Debug Mode:       Enabled"

    # Detect security hardening changes from previous script versions
    detect_legacy_system_state
    local SECURITY_CHANGES=("${LEGACY_SYSTEM_CHANGES[@]+"${LEGACY_SYSTEM_CHANGES[@]}"}")

    if [[ ${#SECURITY_CHANGES[@]} -gt 0 ]]; then
        echo ""
        log_info "Security hardening changes detected (aligning with official XO docs):"
        for change in "${SECURITY_CHANGES[@]}"; do
            echo "  - $change"
        done
    fi

    echo ""
    log_warning "Database and user data in /var/lib/xo-server will NOT be affected."
    log_warning "NFS/CIFS mounts and reverse proxy settings will continue to work."
    echo ""
    confirm_or_skip "Continue with reconfiguration?" || { log_info "Reconfiguration cancelled."; exit 0; }

    # Stop the service
    log_info "Stopping xo-server service..."
    run_cmd timeout 30 sudo systemctl stop xo-server || true

    # Flush stale auth tokens
    flush_redis_tokens

    # Backup current config file
    if [[ -f "/etc/xo-server/config.toml" ]]; then
        log_info "Backing up current configuration..."
        run_cmd sudo cp /etc/xo-server/config.toml "/etc/xo-server/config.toml.backup-$(date +%Y%m%d-%H%M%S)"
        log_success "Backup created"
    fi

    # Backup current systemd service
    if [[ -f "/etc/systemd/system/xo-server.service" ]]; then
        run_cmd sudo cp /etc/systemd/system/xo-server.service "/etc/systemd/system/xo-server.service.backup-$(date +%Y%m%d-%H%M%S)"
    fi

    # Backup current sudoers if present
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        local SUDOERS_FILE="/etc/sudoers.d/xo-server-${SERVICE_USER}"
        if [[ -f "$SUDOERS_FILE" ]]; then
            run_cmd sudo cp "$SUDOERS_FILE" "${SUDOERS_FILE}.backup-$(date +%Y%m%d-%H%M%S)"
        fi
    fi

    # Ensure service user exists before regenerating config (configure_xo does chown)
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        if ! id "$SERVICE_USER" &>/dev/null; then
            log_info "Creating service user: $SERVICE_USER"
            run_cmd sudo useradd -r -m -s /bin/bash "$SERVICE_USER" || true
        fi
    fi

    # Record what the service ran as before, so a switch to root can clean up
    # the previous user's grants further down (create_systemd_service below
    # overwrites the unit this is read from).
    local PREV_SERVICE_USER
    PREV_SERVICE_USER=$(get_previous_service_user)

    # Regenerate configuration
    configure_xo

    # Regenerate systemd service
    create_systemd_service

    # Update sudoers for non-root service user
    configure_sudo

    # Grant XenStore access if a non-root user has credential encryption enabled
    configure_xenstore_access

    # Drop the previous user's sudoers/udev grants if SERVICE_USER became root
    cleanup_stale_service_user "$PREV_SERVICE_USER"

    # Ensure the web ports are open in firewalld (Fedora/RHEL) after any port change
    configure_firewall

    # Clean up legacy group membership and fix file ownership
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        # Remove legacy root group membership from previous script versions
        # The old script added the service user to the root group for file access,
        # which is no longer needed (ownership is set to SERVICE_USER:SERVICE_USER)
        if id -nG "$SERVICE_USER" 2>/dev/null | grep -qw root; then
            log_info "Removing ${SERVICE_USER} from root group (no longer needed)..."
            run_cmd sudo gpasswd -d "$SERVICE_USER" root 2>/dev/null || true
        fi

        # Fix file ownership — migrates from old :root group to SERVICE_USER:SERVICE_USER
        log_info "Updating file ownership for ${SERVICE_USER}..."
        run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
        run_cmd sudo chmod -R o-rwx "$INSTALL_DIR"
        run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" /etc/xo-server
        if [[ -d "$SSL_CERT_DIR" ]]; then
            run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$SSL_CERT_DIR"
        fi
        if [[ -d /var/lib/xo-server ]]; then
            run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" /var/lib/xo-server
            run_cmd sudo chmod 750 /var/lib/xo-server
        fi
        log_success "File ownership updated"
    fi

    # Reload systemd daemon
    log_info "Reloading systemd daemon..."
    run_cmd sudo systemctl daemon-reload

    # Start the service
    log_info "Starting xo-server service..."
    run_cmd sudo systemctl start xo-server
    wait_for_xo_ready

    echo ""
    echo "=============================================="
    log_success "Reconfiguration completed successfully!"
    echo "=============================================="

    echo ""
    log_info "Configuration has been updated from xo-config.cfg"
    local SERVER_IP
    SERVER_IP=$(detect_server_ip)
    log_info "Access Xen Orchestra at:"
    echo "  - http://${SERVER_IP}:${HTTP_PORT}"
    echo "  - https://${SERVER_IP}:${HTTPS_PORT}"
    echo ""
}

# Start the service
start_service() {
    log_info "Starting xo-server service..."
    run_cmd sudo systemctl start xo-server
    wait_for_xo_ready
}

# Poll the XO web interface until it responds or we hit the retry limit.
# Tries HTTPS first, falls back to HTTP.  Does not fail the overall install
# on timeout — a warning is emitted so the operator can investigate.
wait_for_xo_ready() {
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Would poll https://localhost:${HTTPS_PORT} for readiness"
        return 0
    fi

    local RETRIES=10
    local DELAY=6
    local i

    log_info "Waiting for Xen Orchestra to become ready (up to $((RETRIES * DELAY))s)..."

    for (( i=1; i<=RETRIES; i++ )); do
        # Try HTTPS endpoint; fall back to HTTP if HTTPS port is not 443
        if curl -sk --max-time 3 "https://localhost:${HTTPS_PORT}" -o /dev/null -w "%{http_code}" 2>/dev/null \
                | grep -qE '^[23]'; then
            log_success "Xen Orchestra is ready (HTTPS on port ${HTTPS_PORT})"
            return 0
        fi
        if curl -s --max-time 3 "http://localhost:${HTTP_PORT}" -o /dev/null -w "%{http_code}" 2>/dev/null \
                | grep -qE '^[23]'; then
            log_success "Xen Orchestra is ready (HTTP on port ${HTTP_PORT})"
            return 0
        fi
        log_info "  Not ready yet (attempt ${i}/${RETRIES}), retrying in ${DELAY}s..."
        sleep "$DELAY"
    done

    log_warning "Xen Orchestra did not respond after $((RETRIES * DELAY))s."
    log_warning "The service may still be starting. Check: sudo journalctl -u xo-server -n 50"
}

# Print installation summary
# Best-effort primary IP (or hostname) for display in summaries. Always succeeds,
# even on minimal systems without `hostname`/`ip`, so it can't abort under set -e.
detect_server_ip() {
    hostname -I 2>/dev/null | awk '{print $1; exit}' \
        || ip route get 1 2>/dev/null | awk '{print $7; exit}' \
        || hostname 2>/dev/null \
        || echo "your-server-ip"
}

print_summary() {
    echo ""
    echo "=============================================="
    log_success "Xen Orchestra Installation Complete!"
    echo "=============================================="
    echo ""
    echo "Configuration:"
    echo "  - HTTP Port:     ${HTTP_PORT}"
    echo "  - HTTPS Port:    ${HTTPS_PORT}"
    echo "  - Install Dir:   ${INSTALL_DIR}"
    echo "  - SSL Cert Dir:  ${SSL_CERT_DIR}"
    echo "  - Git Branch:    ${GIT_BRANCH}"
    echo "  - Service User:  ${SERVICE_USER:-root}"
    echo ""
    echo "Access Xen Orchestra:"
    local SERVER_IP
    SERVER_IP=$(detect_server_ip)
    local HTTP_URL="http://${SERVER_IP}"
    local HTTPS_URL="https://${SERVER_IP}"
    [[ "$HTTP_PORT" != "80" ]]   && HTTP_URL="${HTTP_URL}:${HTTP_PORT}"
    [[ "$HTTPS_PORT" != "443" ]] && HTTPS_URL="${HTTPS_URL}:${HTTPS_PORT}"
    echo "  - HTTP:  ${HTTP_URL}"
    echo "  - HTTPS: ${HTTPS_URL}"
    echo ""
    echo "Default Credentials:"
    echo "  - Username: admin@admin.net"
    echo "  - Password: admin"
    echo ""
    echo "  These are Xen Orchestra's published defaults - every install starts"
    echo "  with them, so anyone who can reach ${HTTPS_URL} can log in"
    echo "  as a full administrator until you change them. Xen Orchestra holds"
    echo "  your pool's root credentials, so treat this as the first task, not"
    echo "  a later one:"
    echo ""
    echo "    1. Open ${HTTPS_URL} and sign in as admin@admin.net / admin"
    echo "    2. Go to Settings -> Users, or the account menu -> Profile"
    echo "    3. Set a strong, unique password (and enable OTP while you are there)"
    echo ""
    echo "Service Management:"
    echo "  - Start:   sudo systemctl start xo-server"
    echo "  - Stop:    sudo systemctl stop xo-server"
    echo "  - Status:  sudo systemctl status xo-server"
    echo "  - Logs:    sudo journalctl -u xo-server -f"
    echo ""
    echo "To update Xen Orchestra, run:"
    echo "  $0 --update"
    echo ""
    log_warning "HIGHLY RECOMMENDED: change the default admin@admin.net password now."
    log_warning "Until you do, this installation accepts a publicly known login."
    echo ""
}

# Main installation function
install_xo() {
    log_info "Starting Xen Orchestra installation..."

    check_required_commands
    check_not_root
    check_sudo
    check_systemctl
    load_config
    detect_package_manager
    detect_os
    install_dependencies
    check_git
    install_nodejs
    install_yarn
    create_service_user
    setup_redis
    clone_repository
    build_xo
    generate_ssl_certificate
    configure_xo
    create_systemd_service
    configure_sudo
    configure_xenstore_access
    configure_firewall
    start_service
    print_summary
}

# Install XO Proxy on a Xen pool master
install_xo_proxy() {
    log_info "Starting XO Proxy installation..."
    echo ""

    # Detect package manager early
    detect_package_manager

    # Check if expect is installed
    if ! command -v expect &> /dev/null; then
        log_info "Installing expect for automated SSH interaction..."
        pkg_update_soft
        # shellcheck disable=SC2086
        run_cmd $PKG_INSTALL expect
    fi

    # Prompt for Pool Master connection info
    echo "=============================================="
    echo "  Pool Master Connection Information"
    echo "=============================================="
    echo ""

    read -p "IP address of Pool Master: " POOL_MASTER_IP
    if [[ -z "$POOL_MASTER_IP" ]]; then
        log_error "Pool Master IP address is required"
        exit 1
    fi

    read -p "Host username [root]: " HOST_USERNAME
    HOST_USERNAME=${HOST_USERNAME:-root}

    { set +x; } 2>/dev/null
    read -sp "Host password: " HOST_PASSWORD
    echo ""
    if [[ -z "$HOST_PASSWORD" ]]; then
        log_error "Host password is required"
        exit 1
    fi
    [[ "${XO_DEBUG:-0}" == "1" ]] && set -x

    # Test SSH connection
    #
    # `sshpass -e` reading $SSHPASS, never `sshpass -p "$password"`: an argument
    # is visible in the process list for the life of the call, so any other user
    # on this workstation can read the pool master's root password out of `ps`.
    # The environment of another user's process is not readable the same way.
    # This is what dom0_exec already does; these calls predate it.
    log_info "Testing SSH connection to $HOST_USERNAME@$POOL_MASTER_IP..."
    if ! SSHPASS="$HOST_PASSWORD" sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$HOST_USERNAME@$POOL_MASTER_IP" "echo 'Connection successful'" &>/dev/null; then
        # Try installing sshpass if not available
        if ! command -v sshpass &> /dev/null; then
            log_info "Installing sshpass..."
            # shellcheck disable=SC2086
            run_cmd $PKG_INSTALL sshpass
            # Retry connection
            if ! SSHPASS="$HOST_PASSWORD" sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$HOST_USERNAME@$POOL_MASTER_IP" "echo 'Connection successful'" &>/dev/null; then
                log_error "Failed to connect to Pool Master. Please check your credentials."
                exit 1
            fi
        else
            log_error "Failed to connect to Pool Master. Please check your credentials."
            exit 1
        fi
    fi
    log_success "SSH connection successful"

    # Get XO Proxy configuration from user
    echo ""
    echo "=============================================="
    echo "  XO Proxy Configuration"
    echo "=============================================="
    echo ""

    read -p "IP address for proxy [dhcp]: " PROXY_IP
    PROXY_IP=${PROXY_IP:-dhcp}

    read -p "Custom NTP server (leave blank for default): " NTP_SERVER

    echo ""
    echo "=============================================="
    echo "  Xen Orchestra Credentials"
    echo "=============================================="
    echo ""

    read -p "Xen Orchestra login username: " XO_USERNAME
    if [[ -z "$XO_USERNAME" ]]; then
        log_error "Xen Orchestra username is required"
        exit 1
    fi

    { set +x; } 2>/dev/null
    read -sp "Xen Orchestra login password: " XO_PASSWORD
    echo ""
    if [[ -z "$XO_PASSWORD" ]]; then
        log_error "Xen Orchestra password is required"
        exit 1
    fi
    [[ "${XO_DEBUG:-0}" == "1" ]] && set -x

    # Copy the companion expect script to a temp file for execution
    log_info "Creating installation script..."

    local HELPER_SCRIPT="${SCRIPT_DIR}/xo-proxy-helper.exp"
    if [[ ! -f "$HELPER_SCRIPT" ]]; then
        log_error "xo-proxy-helper.exp not found at ${HELPER_SCRIPT}"
        log_error "Ensure xo-proxy-helper.exp is in the same directory as this script."
        exit 1
    fi

    TEMP_SCRIPT=$(mktemp --tmpdir xo-proxy-XXXXXX)
    cp "$HELPER_SCRIPT" "$TEMP_SCRIPT"
    chmod 700 "$TEMP_SCRIPT"

    # Run the expect script
    log_info "Starting XO Proxy installer on Pool Master..."
    log_info "This may take several minutes..."
    echo ""

    OUTPUT=$("$TEMP_SCRIPT" "$POOL_MASTER_IP" "$HOST_USERNAME" "$HOST_PASSWORD" "$PROXY_IP" "$NTP_SERVER" "$XO_USERNAME" "$XO_PASSWORD" 2>&1 | tee /dev/tty)

    # Extract values from output (look after CAPTURED_VALUES marker)
    ACTUAL_PROXY_IP=$(echo "$OUTPUT" | grep "^PROXY_IP=" | tail -1 | cut -d'=' -f2)
    PROXY_UUID=$(echo "$OUTPUT" | grep "^PROXY_UUID=" | tail -1 | cut -d'=' -f2)
    AUTH_TOKEN=$(echo "$OUTPUT" | grep "^AUTH_TOKEN=" | tail -1 | cut -d'=' -f2)

    # Clean up temp script
    rm -f "$TEMP_SCRIPT"

    # Use user-specified IP if not captured
    if [[ -z "$ACTUAL_PROXY_IP" ]]; then
        if [[ "$PROXY_IP" != "dhcp" ]] && [[ "$PROXY_IP" != "DHCP" ]]; then
            ACTUAL_PROXY_IP="$PROXY_IP"
        else
            log_warning "Could not detect DHCP-assigned IP address"
            read -p "Please enter the assigned IP address: " ACTUAL_PROXY_IP
        fi
    fi

    # Validate we got the required information
    if [[ -z "$PROXY_UUID" ]] || [[ -z "$AUTH_TOKEN" ]]; then
        log_warning "Could not automatically extract UUID and/or authentication token"

        if [[ -z "$PROXY_UUID" ]]; then
            read -p "Please enter the XO Proxy UUID: " PROXY_UUID
        fi

        if [[ -z "$AUTH_TOKEN" ]]; then
            read -p "Please enter the authentication token: " AUTH_TOKEN
        fi
    fi

    echo ""
    log_success "XO Proxy installation completed on Pool Master"
    log_info "Proxy IP:   $ACTUAL_PROXY_IP"
    log_info "Proxy UUID: $PROXY_UUID"
    log_info "Auth Token: ${AUTH_TOKEN:0:20}..."

    # Install xo-cli locally
    echo ""
    log_info "Installing xo-cli..."
    if command -v xo-cli &> /dev/null; then
        log_info "xo-cli is already installed"
    else
        if ! command -v npm &> /dev/null; then
            log_error "npm is not installed. Please install Node.js first."
            exit 1
        fi
        run_cmd sudo npm i -g xo-cli
        log_success "xo-cli installed"
    fi

    # Register xo-cli with local Xen Orchestra
    log_info "Registering xo-cli with Xen Orchestra..."

    # Create a temporary expect script for xo-cli registration
    XO_CLI_SCRIPT=$(mktemp --tmpdir xo-cli-XXXXXX)
    chmod 700 "$XO_CLI_SCRIPT"
    cat > "$XO_CLI_SCRIPT" << 'XO_CLI_EXPECT_END'
#!/usr/bin/expect -f

set timeout 30
set username [lindex $argv 0]
set password [lindex $argv 1]

spawn xo-cli --register http://localhost $username

expect {
    -re "Password:" {
        send "$password\r"
        exp_continue
    }
    timeout {
        send_user "\nTimeout during xo-cli registration\n"
        exit 1
    }
    eof
}
XO_CLI_EXPECT_END

    chmod +x "$XO_CLI_SCRIPT"

    if "$XO_CLI_SCRIPT" "$XO_USERNAME" "$XO_PASSWORD"; then
        log_success "xo-cli registered with Xen Orchestra"
    else
        log_warning "Failed to register xo-cli automatically"
        log_info "Please run manually: xo-cli --register http://localhost"
        rm -f "$XO_CLI_SCRIPT"
        exit 1
    fi

    rm -f "$XO_CLI_SCRIPT"

    # Register the proxy with Xen Orchestra
    log_info "Registering XO Proxy with Xen Orchestra..."

    if xo-cli proxy.register authenticationToken="$AUTH_TOKEN" address="$ACTUAL_PROXY_IP:443" vmUuid="$PROXY_UUID"; then
        log_success "XO Proxy registered successfully!"
    else
        log_error "Failed to register XO Proxy"
        log_info "You can register manually with:"
        log_info "xo-cli proxy.register authenticationToken=\"$AUTH_TOKEN\" address=\"$ACTUAL_PROXY_IP:443\" vmUuid=\"$PROXY_UUID\""
        exit 1
    fi

    # Check if license check disabling is enabled in config
    if [[ "${DISABLE_LICENSE_CHECK:-false}" == "true" ]]; then
        log_info "Disabling license check on XO Proxy..."
        # -e/$SSHPASS rather than -p: see the note on the connection test above.
        if SSHPASS="$HOST_PASSWORD" sshpass -e ssh -o StrictHostKeyChecking=accept-new "$HOST_USERNAME@$POOL_MASTER_IP" 'bash -s' << 'REMOTE_LICENSE_PATCH'
set -e
APPLIANCE_FILE=$(find /opt/xo-proxy -name 'appliance.mjs' 2>/dev/null | head -1)
if [[ -z "$APPLIANCE_FILE" ]]; then
    echo "WARNING: appliance.mjs not found, skipping license bypass"
    exit 0
fi
python3 - "$APPLIANCE_FILE" << 'PYEOF'
import sys, re
fname = sys.argv[1]
with open(fname) as f:
    content = f.read()
patched = re.sub(
    r'((\s*)getSelfLicense\(\) \{).*?(\n\2\})',
    r'\1\n\2    // modified to disable license check for XO from sources\n\2    return true\3',
    content,
    flags=re.DOTALL
)
with open(fname, 'w') as f:
    f.write(patched)
PYEOF
systemctl restart xo-proxy
REMOTE_LICENSE_PATCH
        then
            log_success "License check disabled on XO Proxy"
        else
            log_warning "Failed to disable license check on XO Proxy"
            log_info "To manually disable: patch /opt/xo-proxy/app/mixins/appliance.mjs and restart xo-proxy service"
        fi
    fi

    # Print summary
    echo ""
    echo "=============================================="
    log_success "XO Proxy Installation Complete!"
    echo "=============================================="
    echo ""
    echo "Proxy Details:"
    echo "  - IP Address: $ACTUAL_PROXY_IP"
    echo "  - UUID:       $PROXY_UUID"
    echo "  - Auth Token: ${AUTH_TOKEN:0:20}..."
    echo ""
    echo "The proxy has been registered with your Xen Orchestra instance."
    echo "You can manage it from the Xen Orchestra web interface."
    echo ""
}

# ============================================================================
# Deploy Xen Orchestra to a new VM on a XenServer/XCP-ng pool
#
# Unlike every other operation in this script, --deploy runs on your
# workstation rather than on the machine XO will live on. It:
#
#   1. Opens one multiplexed SSH connection to the pool master and drives `xe`
#      over it (the pool master already has `xe`; your workstation needs no
#      XAPI tooling at all).
#   2. Creates a VM and streams a stock Debian cloud image straight from
#      cloud.debian.org into its root disk, so nothing lands on dom0's small
#      root filesystem and there is no appliance image to host or keep current.
#   3. Attaches a cloud-init NoCloud config drive that creates the admin user,
#      installs your SSH key, sets the static address, and clones this repo.
#   4. SSHes into the finished VM and runs this same script with
#      --install --non-interactive, streaming the output to your terminal.
#
# The result is an ordinary VM with a checkout of this repo in it, so --update
# and friends work there from then on exactly as they do anywhere else.
# ============================================================================

# Debian cloud image used for the guest. Overridable from the environment for
# testing or to pin an older release. The `.raw` variant is deliberate: XAPI
# imports raw disks natively, so nothing has to convert a qcow2 and no qemu-img
# is needed on either end.
#
# `generic`, not `genericcloud`. The two are published side by side, are the
# same size, and differ in the kernel they carry:
#
#   genericcloud  vmlinuz-6.12.107+deb13-cloud-amd64
#   generic       vmlinuz-6.12.107+deb13-amd64
#
# The cloud kernel is trimmed for headless VMs and ships neither the `bochs`
# framebuffer driver nor a compiled-in `efi-framebuffer`. XCP-ng documents the
# consequence (https://xcp-ng.org/docs/guests.html, "Distorted display console
# on Ubuntu UEFI VMs"): with no suitable driver the guest falls back to
# simple-framebuffer, which OVMF's VGA initialisation does not agree with, and
# the console renders as scrambled colour. The VM itself is fine -- it boots,
# gets an IP and runs the guest agent -- so nothing reports an error. Under BIOS
# the guest uses plain VGA text mode and the problem does not appear, which is
# what makes it look like a firmware bug rather than a missing driver.
XO_DEPLOY_IMAGE_VERSION="${XO_DEPLOY_IMAGE_VERSION:-13}"
XO_DEPLOY_IMAGE_RELEASE="${XO_DEPLOY_IMAGE_RELEASE:-trixie}"
XO_DEPLOY_IMAGE_URL="${XO_DEPLOY_IMAGE_URL:-https://cloud.debian.org/images/cloud/${XO_DEPLOY_IMAGE_RELEASE}/latest/debian-${XO_DEPLOY_IMAGE_VERSION}-generic-amd64.raw}"

# The raw image is 3 GB; the root VDI must be at least that large for the
# import to fit, and cloud-init's growpart expands the filesystem to whatever
# size we actually create.
XO_DEPLOY_MIN_DISK_GB=10
# The admin password is the credential the finished VM is left with -- the
# deploy key is destroyed on the way out -- so it carries more weight than a
# convenience password and the floor is set accordingly.
XO_DEPLOY_MIN_PASSWORD_LEN=12

# Populated by the deploy_* prompt functions below.
DEPLOY_SSH_CTL=""
DEPLOY_WORKDIR=""
DEPLOY_CHOICE=""
DEPLOY_ADMIN_PASSWORD_HASH=""
DEPLOY_ADMIN_SSH_PWAUTH="false"
DEPLOY_REPO_DIR="/opt/install_xen_orchestra"
DEPLOY_CIDATA_VDI=""
DEPLOY_CIDATA_VBD=""
DEPLOY_CONFIG_BASE=""
DEPLOY_CONFIG_BASE_LABEL="sample-xo-config.cfg (defaults)"
DEPLOY_VM_STARTED="false"
DEPLOY_VM_UUID=""
DEPLOY_ROOT_VDI=""
# Set once the deploy has actually finished. deploy_cleanup runs on every exit,
# success included, so the failure paths it drives need a way to tell the two
# apart -- without this, a perfectly good deploy ends by offering to destroy
# the VM it just built.
DEPLOY_SUCCEEDED="false"
DEPLOY_SUDO_HARDENED="false"
# The operator's own public key, if they gave one, and the throwaway deployment
# key's public half, which deploy_revoke_deploy_key needs in order to find and
# remove exactly its own line from the guest's authorized_keys.
DEPLOY_USER_PUBKEY=""
DEPLOY_PUBKEY=""
DEPLOY_KEY_REVOKED="false"
# Declared here so the post-install hardening steps can test it under `set -u`
# even on a path that never reached deploy_wait_for_guest.
DEPLOY_SSH_OPTS=()
# The run-scoped known_hosts holding the pool master key deploy_verify_host_key
# checked. Empty until then, which is what keeps dom0_exec usable under `set -u`
# on the paths that run before the check.
DEPLOY_POOL_KNOWN_HOSTS=""

# Suppressing `set -x` around anything that touches the pool password.
#
# XO_DEBUG=1 traces the whole run, and the deploy path hands the password to
# sshpass and into XAPI's XML-RPC body on nearly every call — all of which
# xtrace prints verbatim, which is exactly what the "sensitive values are
# masked" note at the top of this file promises it does not do. The functions
# that touch the password therefore open with:
#
#     local -     # bash restores the shell options when this function returns
#     set +x
#
# which is nesting-safe: each function restores the state it was called with,
# so deploy_xapi_login calling dom0_exec puts tracing back exactly once.

# Escape a value for an XML text node.
#
# XAPI is spoken to over XML-RPC, so a perfectly valid password containing &,
# < or > would otherwise produce a malformed request and a login failure with
# no visible cause.
xml_escape() {
    local s="$1"
    # The backslashes matter: since bash 5.2 an unquoted & in the replacement
    # of ${var//pat/repl} stands for the matched text, so "&lt;" would expand
    # to "<lt;". \& is the literal ampersand on every bash that runs this.
    s="${s//&/\&amp;}"
    s="${s//</\&lt;}"
    s="${s//>/\&gt;}"
    printf '%s' "$s"
}

# Validate a dotted-quad IPv4 address, octet by octet.
#
# The shape regex used at the prompts accepts 999.999.999.999, which would go
# straight into cloud-init's network-config and produce a guest that never
# comes up — and that we would then wait 10 minutes for.
is_ipv4() {
    local addr="$1" octet
    [[ "$addr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    for octet in $addr; do
        (( 10#$octet <= 255 )) || return 1
    done
    return 0
}

# Validate a TCP port. The installer inside the VM rejects anything outside
# 1-65535, but by the time it runs the VM already exists — so the same bound
# is enforced at the prompt.
is_port() {
    [[ "$1" =~ ^[0-9]+$ ]] || return 1
    (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

# Accept only a URL we are willing to hand to a remote shell.
#
# The image URL reaches the pool master inside a single-quoted `curl` argument.
# Inside single quotes the one character that can break out is another single
# quote; whitespace and control characters are never valid in a URL anyway and
# would split the argument.
is_safe_url() {
    case "$1" in
        http://*|https://*) ;;
        *) return 1 ;;
    esac
    [[ "$1" != *"'"* ]] || return 1
    [[ "$1" != *[[:space:]]* ]] || return 1
    return 0
}

# Run a command on the pool master.
#
# Every call multiplexes over one master SSH connection, so authentication
# happens exactly once no matter how many `xe` commands the deploy runs.
#
# sshpass is used when present — it feeds the password from $SSHPASS rather
# than argv, keeping it out of `ps`, and means a single prompt for the whole
# run. It is not required though: without it plain ssh asks for the password
# itself when the master connection opens, which is one extra prompt and no
# package to install. Set by deploy_connect_pool_master.
DEPLOY_AUTH_MODE="prompt"

dom0_exec() {
    # sshpass reads the password from the environment, which xtrace would print.
    local -
    set +x

    local rc=0
    local common=(
        -o ControlMaster=auto
        -o ControlPath="$DEPLOY_SSH_CTL"
        -o ControlPersist=600
        -o ConnectTimeout=15
    )

    # Bind the connection to the key deploy_verify_host_key actually checked.
    #
    # Fingerprinting a key and then connecting under `accept-new` against the
    # default known_hosts verifies one transaction and trusts another: nothing
    # stops a different key -- or the same host's RSA key, when the ED25519 one
    # was what was shown -- being accepted at connect time. Pinning the scanned
    # key into a run-scoped file and demanding StrictHostKeyChecking=yes is what
    # makes the check bind to the session that carries the host password. This
    # is the same pattern deploy_wait_for_guest already uses for the guest.
    #
    # Before the check has run (DEPLOY_POOL_KNOWN_HOSTS empty) there is nothing
    # to pin against, so `accept-new` stands -- but deploy_connect_pool_master
    # calls deploy_verify_host_key before the first dom0_exec, so no call that
    # carries the password takes this branch.
    if [[ -n "$DEPLOY_POOL_KNOWN_HOSTS" && -s "$DEPLOY_POOL_KNOWN_HOSTS" ]]; then
        common+=(
            -o UserKnownHostsFile="$DEPLOY_POOL_KNOWN_HOSTS"
            -o StrictHostKeyChecking=yes
        )
    else
        common+=(-o StrictHostKeyChecking=accept-new)
    fi
    if [[ "$DEPLOY_AUTH_MODE" == "sshpass" ]]; then
        SSHPASS="$HOST_PASSWORD" sshpass -e ssh "${common[@]}" \
            "${HOST_USERNAME}@${POOL_MASTER_IP}" "$@" || rc=$?
    else
        ssh "${common[@]}" "${HOST_USERNAME}@${POOL_MASTER_IP}" "$@" || rc=$?
    fi
    return $rc
}

# Run an `xe` command on the pool master and return its output with the
# trailing whitespace and CRs that xe likes to emit stripped off.
dom0_xe() {
    dom0_exec "xe $*" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# ---------------------------------------------------------------------------
# Getting bytes into a VDI
#
# `xe vdi-import filename=/dev/stdin` does not work: XCP-ng 8.3 fails it with
# VDI_IO_ERROR whether the pipe comes from a local command or from SSH, because
# XAPI needs a seekable source of known length. XAPI's own HTTP endpoint,
# /import_raw_vdi, is the supported path, and it likewise rejects chunked
# transfer encoding.
#
# So we PUT to that endpoint from the pool master itself, streaming, with the
# length supplied by hand:
#
#   curl <image> | curl -T - -H 'Transfer-Encoding:' -H 'Content-Length: N'
#
# -T - streams stdin through a read callback instead of buffering it, which
# matters enormously: the obvious alternative (--data-binary @-) reads the
# whole body into memory first and dies with "out of memory" on a 1 GiB
# payload, let alone a 3 GiB image.
#
# Running it on the pool master means the image never crosses the operator's
# link and never lands on dom0's filesystem either.
#
# All of this is verified by tests/probe-xapi-deploy.sh against a real host.
# ---------------------------------------------------------------------------

DEPLOY_SESSION=""

# Log in to XAPI and set DEPLOY_SESSION to the resulting opaque reference.
#
# The login runs on the pool master against localhost, so --deploy needs only
# SSH to the host and never requires the operator's machine to reach port 443.
# The XML body goes over stdin and straight into curl's stdin on the far end:
# it never appears in dom0's process list and never lands on dom0's disk, where
# a fixed /tmp path would have been readable by any other local account for the
# duration of the request (and would have collided with a concurrent deploy).
deploy_xapi_login() {
    local -
    set +x

    local xml
    xml=$(printf '<?xml version="1.0"?><methodCall><methodName>session.login_with_password</methodName><params><param><value><string>%s</string></value></param><param><value><string>%s</string></value></param></params></methodCall>' \
        "$(xml_escape "$HOST_USERNAME")" "$(xml_escape "$HOST_PASSWORD")")

    local reply
    reply=$(printf '%s' "$xml" | dom0_exec \
        "curl -sk --max-time 30 -H 'Content-Type: text/xml' \
              --data-binary @- https://localhost/" 2>/dev/null) || true

    DEPLOY_SESSION=$(grep -o 'OpaqueRef:[A-Za-z0-9._-]*' <<< "$reply" | head -1 || true)

    if [[ -z "$DEPLOY_SESSION" ]]; then
        log_error "Could not log in to XAPI on the pool master."
        log_error "SSH works, so this is usually a wrong password for the XAPI user."
        exit 1
    fi
}

# Release the XAPI session. Best-effort: sessions expire on their own.
deploy_xapi_logout() {
    [[ -n "$DEPLOY_SESSION" ]] || return 0
    local xml
    xml=$(printf '<?xml version="1.0"?><methodCall><methodName>session.logout</methodName><params><param><value><string>%s</string></value></param></params></methodCall>' \
        "$(xml_escape "$DEPLOY_SESSION")")
    printf '%s' "$xml" | dom0_exec \
        "curl -sk --max-time 10 -H 'Content-Type: text/xml' \
              --data-binary @- https://localhost/ >/dev/null" >/dev/null 2>&1 || true
    DEPLOY_SESSION=""
}

# Stream a remote image straight into a VDI, entirely on the pool master.
# Arguments: VDI uuid, source URL
# The streaming import's remote program, in its own function so it survives one
# round of shell quoting instead of three, and so the tests can read it.
#
# The pipeline is built by hand rather than written as `curl | curl` because a
# plain pipe deadlocks when the download dies: the upload has already promised
# XAPI an exact Content-Length, so it sits waiting to send bytes that are never
# coming while XAPI waits for them, and neither notices. --speed-time does not
# save it -- by then curl is waiting for a response, not transferring, so the
# speed meter has stopped ticking and only --max-time 3600 eventually fires.
# Watching the download's exit status and killing the upload ends it at once.
deploy_stream_script() {
    cat <<'STREAM_EOF'
set -o pipefail
url=$1; size=$2; target=$3

# mktemp -d, not mktemp -u: -u hands back a name without creating anything,
# leaving a window in dom0's world-writable /tmp where another process can take
# the path first. A directory is created atomically at mode 700, so the fifo
# inside it cannot be pre-empted or opened by anyone else.
d=$(mktemp -d) || exit 1
trap 'rm -rf "$d"' EXIT
fifo="$d/pipe"
mkfifo "$fifo" || exit 1

curl -fsS -L --speed-limit 1024 --speed-time 60 --max-time 3600 "$url" > "$fifo" &
dl=$!

# -L: on a multi-host pool XAPI answers 302 to whichever host can see the SR,
# and an unfollowed redirect uploads nothing while exiting 0. A redirected PUT
# from a fifo cannot be replayed, so the body is read once and the hop is made
# before any of it is sent -- which is what --post302 with -T - gives us here.
curl -sk -f -L --post301 --post302 --post303 \
     --speed-limit 1024 --speed-time 60 --max-time 3600 -T - \
     -H 'Transfer-Encoding:' -H "Content-Length: $size" "$target" < "$fifo" &
ul=$!

if ! wait "$dl"; then
    kill "$ul" 2>/dev/null
    wait "$ul" 2>/dev/null
    exit 1
fi
wait "$ul"
STREAM_EOF
}

# Get the cloud image into a VDI, staging it on the host by preference.
#
# Check a staged image against the checksum its origin publishes.
#
# The size check above catches a download that was cut short. It cannot catch a
# download that arrived complete from the wrong place -- a poisoned mirror, a
# hijacked redirect, a stale cache -- because a substituted image has a
# perfectly consistent Content-Length. Only a cryptographic digest separates
# those, and the whole point of this image is that it becomes the appliance
# holding the pool's root credentials.
#
# Two sources, in order of authority:
#
#   XO_DEPLOY_IMAGE_SHA512  an explicit pin. Like XO_DEPLOY_POOL_FINGERPRINT,
#                           setting it means the check is mandatory: if it
#                           cannot be made, the deploy stops.
#   SHA512SUMS              fetched from the image's own directory, which is
#                           where Debian publishes it. Best effort, because a
#                           private mirror may not carry one -- a missing file
#                           warns, a mismatched digest always fails.
#
# Fetching the sums over the same connection as the image is not the strong
# guarantee a detached signature would be; it defends against a bad mirror or a
# corrupted cache, not against an attacker holding the TLS session for both
# requests. Pin the digest when that distinction matters.
#
# Returns 0 when verified or legitimately skipped, 1 when the image must not be
# imported.
deploy_verify_image_checksum() {
    local url="$1" tmp="$2"
    local pinned="${XO_DEPLOY_IMAGE_SHA512:-}"
    local want=""

    if [[ -n "$pinned" ]]; then
        want="$pinned"
        log_info "  verifying the image against XO_DEPLOY_IMAGE_SHA512..."
    else
        # Both derived from a URL is_safe_url has already cleared of quotes and
        # whitespace, so they stay safe inside the single-quoted remote argument.
        local base="${url##*/}"; base="${base%%\?*}"
        local dir="${url%/*}"

        local sums
        sums=$(dom0_exec "curl -fsSL --max-time 120 '${dir}/SHA512SUMS' 2>/dev/null" 2>/dev/null | tr -d '\r' || true)
        if [[ -n "$sums" ]]; then
            # Lines are "<digest>  <name>"; coreutils marks binary mode with a
            # leading '*' on the name.
            want=$(awk -v f="$base" '$2 == f || $2 == "*" f { print $1; exit }' <<< "$sums")
        fi

        if [[ -z "$want" ]]; then
            log_warning "  no published SHA512SUMS entry for $(basename "$base") at the image origin."
            log_warning "  The image cannot be verified, only size-checked. Set"
            log_warning "  XO_DEPLOY_IMAGE_SHA512 to require a digest match."
            return 0
        fi
        log_info "  verifying the image against the origin's SHA512SUMS..."
    fi

    if [[ ! "$want" =~ ^[a-fA-F0-9]{128}$ ]]; then
        log_error "The expected SHA-512 digest is not 128 hex characters:"
        log_error "  ${want}"
        return 1
    fi

    local got
    got=$(dom0_exec "sha512sum '${tmp}' 2>/dev/null | awk '{print \$1}'" | tr -d '\r')
    if [[ ! "$got" =~ ^[a-fA-F0-9]{128}$ ]]; then
        # A pin is a demand for proof, so failing to produce one is fatal.
        if [[ -n "$pinned" ]]; then
            log_error "Could not compute the image's SHA-512 on the pool master, and"
            log_error "XO_DEPLOY_IMAGE_SHA512 is set. Refusing to import it unverified."
            return 1
        fi
        log_warning "  could not compute the image's checksum on the pool master; skipping."
        return 0
    fi

    if [[ "${got,,}" != "${want,,}" ]]; then
        log_error "The downloaded image does not match its published checksum."
        log_error "  expected: ${want,,}"
        log_error "  actual:   ${got,,}"
        log_error "Refusing to import it. This is a corrupted download or the wrong"
        log_error "file; if it repeats, treat the mirror as suspect."
        return 1
    fi

    log_success "  image checksum verified"
    return 0
}

# Staging wins on every count that matters. The download lands in a file, so it
# can be resumed with -C - and retried, and its size can be checked against
# what the server advertised before a byte reaches the disk. Streaming can do
# none of those: one dropped TLS record and the transfer is gone, with no way
# to resume a pipe that has already fed bytes to a fixed-Content-Length PUT.
# Over a link that drops the occasional record -- which a multi-gigabyte
# transfer will eventually meet -- streaming fails every attempt while staging
# rides it out.
#
# So streaming is now what it should always have been: the fallback for a host
# without the few gigabytes of scratch space staging needs.
deploy_import_vdi_from_url() {
    local vdi="$1" url="$2"

    # `|| rc=$?` rather than a bare call: under `set -e` a function returning
    # non-zero on its own line takes the script down with it, so the fallback
    # below would never be reached -- a host short on scratch space would fail
    # the whole deploy instead of streaming the image in.
    local rc=0
    deploy_import_vdi_staged "$vdi" "$url" || rc=$?

    # Anything but "no room to stage" is a real failure. Falling through to
    # streaming after a download that already exhausted its retries would just
    # spend another few minutes arriving at the same place.
    if (( rc != 2 )); then
        return $rc
    fi

    # A pinned digest cannot be honoured by the streaming path: the bytes go
    # straight from the origin into the VDI, so there is no file to hash and
    # nothing to reject if it does not match. Silently importing an unverified
    # image because the host was short on scratch space would make the pin mean
    # whatever the disk happened to allow, so this stops instead.
    if [[ -n "${XO_DEPLOY_IMAGE_SHA512:-}" ]]; then
        log_error "Not enough scratch space on the pool master to stage the image, and"
        log_error "XO_DEPLOY_IMAGE_SHA512 is set. A streamed image cannot be verified,"
        log_error "so it will not be imported."
        log_error "Free up space in /var/tmp on the pool master and retry."
        return 1
    fi

    log_warning "Not enough scratch space on the pool master to stage the image."
    log_warning "Falling back to streaming it straight into the disk."
    log_warning "This cannot resume a broken transfer, so a flaky link may fail it."
    log_warning "It also cannot be checksummed -- nothing verifies what arrives."

    # The PUT needs an exact Content-Length, so ask the origin how big the
    # image is before starting. -L follows the redirects Debian's mirrors use.
    local size
    size=$(dom0_exec "curl -fsSLI '${url}' 2>/dev/null | tr -d '\r' | grep -i '^content-length:' | tail -1 | awk '{print \$2}'" | tr -d '\r')

    if [[ -z "$size" || ! "$size" =~ ^[0-9]+$ ]]; then
        log_error "The image server did not report a size, so it cannot be streamed"
        log_error "either. Free up space in /var/tmp on the pool master and retry."
        return 1
    fi

    log_info "  image is $(( size / 1048576 )) MiB; streaming it into the disk"

    local vdi_ref
    if ! vdi_ref=$(deploy_vdi_ref "$vdi"); then
        log_error "Could not resolve the disk ${vdi} to an XAPI reference."
        return 1
    fi
    local task
    task=$(deploy_task_create "import ${vdi}")
    local task_q=""
    [[ "$task" =~ ^OpaqueRef: ]] && task_q="&task_id=${task}"

    local target="https://localhost/import_raw_vdi?session_id=${DEPLOY_SESSION}&vdi=${vdi_ref}&format=raw${task_q}"
    # A here-string, not a pipe: if the remote shell ever exits before reading
    # the program, a pipe hands back SIGPIPE (141) instead of whatever actually
    # went wrong. This is also how the config-drive upload feeds dom0_exec.
    local rc=0
    dom0_exec "bash -s -- '${url}' '${size}' '${target}'" <<< "$(deploy_stream_script)" || rc=$?
    if (( rc == 0 )) && ! deploy_task_check "$task"; then
        rc=1
    fi
    deploy_task_destroy "$task"
    return $rc
}

# Translate a VDI uuid into the opaque reference XAPI's HTTP endpoints expect.
#
# `xe vdi-create` returns a uuid, but /import_raw_vdi takes an OpaqueRef. Given
# a uuid it does not reject the request outright: it accepts the connection,
# writes a few kilobytes of header, and then stops -- leaving a VDI with about
# 19 KB in it and an import that reported success. That failure looks exactly
# like a disk too small for its image, which is the wrong thing to go and fix.
deploy_vdi_ref() {
    local uuid="$1" ref=""
    ref=$(dom0_exec "xe vdi-param-get uuid='${uuid}' param-name=_ref 2>/dev/null" | tr -d '\r')

    # Not every XAPI build exposes _ref as a parameter. Ask the API directly
    # when it does not, rather than falling back to the uuid and failing in the
    # confusing way described above.
    if [[ ! "$ref" =~ ^OpaqueRef: ]]; then
        local xml
        xml=$(printf '<?xml version="1.0"?><methodCall><methodName>VDI.get_by_uuid</methodName><params><param><value><string>%s</string></value></param><param><value><string>%s</string></value></param></params></methodCall>' \
            "$(xml_escape "$DEPLOY_SESSION")" "$(xml_escape "$uuid")")
        local reply
        reply=$(dom0_exec "curl -sk -H 'Content-Type: text/xml' --data-binary @- https://localhost/ 2>/dev/null" <<< "$xml" || true)
        ref=$(grep -o 'OpaqueRef:[A-Za-z0-9._-]*' <<< "$reply" | head -1 || true)
    fi

    [[ "$ref" =~ ^OpaqueRef: ]] || return 1
    printf '%s' "$ref"
}

# ---------------------------------------------------------------------------
# Watching an import through XAPI's task, not through curl's exit status
#
# /import_raw_vdi answers the HTTP request as soon as it has accepted the
# stream. Whether the import then *worked* is reported on a task object, and
# only there: an import that dies inside XAPI still returns 200 and still lets
# curl exit 0, leaving a VDI with a few kilobytes of header in it and a caller
# that believes it succeeded. That is exactly the failure this code spent
# several runs mistaking for a disk that was too small.
#
# So every import creates a task first, passes its reference as task_id, and
# reads status and error_info back afterwards. XAPI's own description of the
# failure is worth more than any guess made from the outside.
# ---------------------------------------------------------------------------

# Send one XML-RPC call to XAPI on the pool master and print the raw response.
# Arguments: method name, then each parameter as an already-escaped string.
deploy_xapi_call() {
    local method="$1"; shift
    local xml params=""
    local p
    for p in "$@"; do
        params+="$(printf '<param><value><string>%s</string></value></param>' "$(xml_escape "$p")")"
    done
    xml=$(printf '<?xml version="1.0"?><methodCall><methodName>%s</methodName><params>%s</params></methodCall>' \
        "$method" "$params")
    dom0_exec "curl -sk --max-time 30 -H 'Content-Type: text/xml' \
        --data-binary @- https://localhost/ 2>/dev/null" <<< "$xml" || true
}

# Create a task for an import to report itself through. Prints its OpaqueRef,
# or nothing when the task could not be made -- in which case the caller goes
# ahead without one rather than refusing to import at all.
deploy_task_create() {
    local label="$1"
    local reply
    reply=$(deploy_xapi_call "task.create" "$DEPLOY_SESSION" "$label" "$label")
    grep -o 'OpaqueRef:[A-Za-z0-9._-]*' <<< "$reply" | tail -1 || true
}

# Read a finished task and decide whether the import actually worked.
#
# Returns 0 when the task says success, 1 otherwise, printing whatever XAPI
# gave as the reason. A task that cannot be read is not treated as a failure:
# the template build still reads the imported disk's partition table behind
# this, and a missing task should not turn a good import into a reported one.
deploy_task_check() {
    local task="$1"
    if [[ ! "$task" =~ ^OpaqueRef: ]]; then
        # Silence here is not evidence of success: it means the task was never
        # made, so nothing was watching the import at all. Say so rather than
        # letting a missing task read as a clean run.
        log_warning "  no XAPI task was created for this import, so it was not watched."
        return 0
    fi

    local reply status
    reply=$(deploy_xapi_call "task.get_status" "$DEPLOY_SESSION" "$task")
    status=$(sed -n 's/.*<value>\(pending\|success\|failure\|cancelling\|cancelled\)<\/value>.*/\1/p' <<< "$reply" | head -1)

    # A pending task here means XAPI answered the HTTP request before it had
    # finished writing. Give it a bounded moment rather than calling it broken.
    local waited=0
    while [[ "$status" == "pending" ]] && (( waited < 60 )); do
        sleep 2; waited=$(( waited + 2 ))
        reply=$(deploy_xapi_call "task.get_status" "$DEPLOY_SESSION" "$task")
        status=$(sed -n 's/.*<value>\(pending\|success\|failure\|cancelling\|cancelled\)<\/value>.*/\1/p' <<< "$reply" | head -1)
    done

    case "$status" in
        success) return 0 ;;
        pending)
            log_warning "  the import task was still pending after 60s; not waiting further."
            return 0 ;;
        "")
            # An unparsed reply is not a success. Print what XAPI actually sent
            # so the next run does not have to guess at it as well.
            log_warning "  could not read the import task's status. XAPI replied:"
            log_warning "    ${reply:0:400}"
            return 0 ;;
    esac

    log_error "  XAPI reported the import as ${status}:"
    local err
    err=$(deploy_xapi_call "task.get_error_info" "$DEPLOY_SESSION" "$task")
    # error_info is an array of strings; print each one rather than the XML.
    # error_info is an array of strings that XAPI returns on a single line, so
    # each <string> has to be split out rather than matched one per line -- the
    # first element is the error code (SR_BACKEND_FAILURE_44 and friends) and
    # dropping it loses the half worth searching for.
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] && log_error "    ${line}"
    done < <(printf '%s' "$err" | grep -o '<string>[^<]*</string>' \
        | sed -e 's/<string>//' -e 's|</string>||' | head -8)
    return 1
}

# Release a task once it has been read. XAPI keeps finished tasks around until
# they are destroyed, and a run that builds several templates would otherwise
# leave one behind for each import.
deploy_task_destroy() {
    local task="$1"
    [[ "$task" =~ ^OpaqueRef: ]] || return 0
    deploy_xapi_call "task.destroy" "$DEPLOY_SESSION" "$task" >/dev/null 2>&1 || true
}

# The default import path: download to dom0, PUT from the file, delete it.
#
# Needs the image's size free in /var/tmp, and pays an extra disk round trip
# for it. What that buys is every property the streaming path cannot have -- a
# download that resumes and retries, and a size that can be checked before
# anything is written into the VDI.
#
# Returns 0 on success, 2 when there is not enough scratch space to try (the
# caller falls back to streaming), and 1 on any other failure.
deploy_import_vdi_staged() {
    local vdi="$1" url="$2"
    # $$ is this workstation's shell PID, not the pool master's, so the path is
    # not unique on the host it actually lives on: two runs from the same shell
    # -- or from different machines whose PIDs happen to coincide -- land on the
    # same file. That matters because the download resumes with `curl -C -`,
    # which treats a leftover file as progress: a stale complete one is
    # "finished" instantly and a stale truncated one is topped up to the wrong
    # length. Naming the file after the VDI it is destined for makes it unique
    # per import and self-cleaning across retries of the same build.
    local tmp="/var/tmp/xo-image-${vdi}.raw"

    # Size the check on the image actually being staged, not on the stock
    # Debian one: XO_DEPLOY_IMAGE_URL and the release overrides can point at
    # something much larger (which would fill /var/tmp mid-download) or much
    # smaller (which a flat 4 GiB floor would reject for no reason). Only when
    # the origin refuses to report a length do we fall back to that floor.
    local need_mb=4096 size=""
    size=$(dom0_exec "curl -fsSLI '${url}' 2>/dev/null | tr -d '\r' | grep -i '^content-length:' | tail -1 | awk '{print \$2}'" 2>/dev/null | tr -d '\r' || true)
    if [[ "$size" =~ ^[0-9]+$ ]] && (( size > 0 )); then
        # A little headroom over the image itself for filesystem overhead.
        need_mb=$(( size / 1048576 + 256 ))
    fi

    # Returns 2, not 1, when there is no room: this is the one failure the
    # caller can do something about, by falling back to a streaming import that
    # needs no scratch space. Every other failure here is terminal.
    #
    # The `=~ ^[0-9]+$` is load-bearing, not tidiness, and matches the guards on
    # `size` above and `got` below. `(( ))` evaluates an array subscript as an
    # arithmetic expression, and expands it first -- so a non-numeric answer from
    # the host, `PATH[$(...)]`, is *executed here*, on the workstation, rather
    # than rejected. That turns a hostile or impersonated pool master into local
    # code execution, so the value is checked before it reaches `(( ))` at all.
    #
    # `set -u` is not the guard it looks like: it stops the payload naming an
    # *unset* variable (`x[$(...)]` aborts), but any bound name -- PATH, HOME, or
    # anything this script declares -- sails straight through it.
    local free_mb
    free_mb=$(dom0_exec "df -BM --output=avail /var/tmp 2>/dev/null | tail -1 | tr -d ' M'" | tr -d '\r')
    if [[ "$free_mb" =~ ^[0-9]+$ ]] && (( free_mb < need_mb )); then
        log_info "  /var/tmp on the pool master has ${free_mb} MiB free; staging needs ${need_mb} MiB."
        return 2
    fi

    # Unlike the streaming path, this one lands in a file, so a broken transfer
    # can be resumed rather than restarted: -C - picks up from the bytes
    # already on disk and --retry handles the transient TLS and connection
    # failures that a multi-gigabyte download over one connection will
    # eventually hit ("decryption failed or bad record mac" being the classic).
    # The stall guard is here too, so a connection that goes quiet is retried
    # in a minute instead of hanging until --max-time.
    #
    # --progress-bar because this is several minutes of silence otherwise, and
    # silence on the longest step of the deploy reads as a hang worth killing.
    # Sweep leftovers from the previous naming scheme, which used the calling
    # shell's PID and so could never be matched again. They are gigabyte-sized
    # and nothing else will reclaim them.
    dom0_exec "rm -f /var/tmp/xo-deploy-image-*.raw" >/dev/null 2>&1 || true

    log_info "  downloading the image to the pool master (resumable)..."
    if ! dom0_exec "curl -fL --progress-bar -o '${tmp}' -C - \
            --retry 5 --retry-delay 3 --retry-all-errors \
            --speed-limit 1024 --speed-time 60 --max-time 3600 '${url}'"; then
        log_error "Failed to download the image on the pool master."
        log_error "Check outbound access from the host:"
        log_error "  ssh ${HOST_USERNAME}@${POOL_MASTER_IP} curl -I '${url}'"
        dom0_exec "rm -f '${tmp}'" >/dev/null 2>&1 || true
        return 1
    fi

    # A truncated download that curl reported as fine still has to be caught:
    # importing it would produce a VM that boots to a corrupt filesystem.
    if [[ "$size" =~ ^[0-9]+$ ]] && (( size > 0 )); then
        local got
        got=$(dom0_exec "stat -c %s '${tmp}' 2>/dev/null" | tr -d '\r')
        if [[ "$got" =~ ^[0-9]+$ ]] && (( got != size )); then
            log_error "The staged image is ${got} bytes; the server said ${size}."
            log_error "Refusing to import a truncated image."
            dom0_exec "rm -f '${tmp}'" >/dev/null 2>&1 || true
            return 1
        fi
    fi

    # After the size check and before anything reaches the VDI: a bad image is
    # cheap to delete now and expensive to discover once it is the appliance.
    if ! deploy_verify_image_checksum "$url" "$tmp"; then
        dom0_exec "rm -f '${tmp}'" >/dev/null 2>&1 || true
        return 1
    fi

    # Prove the staged file is the whole image before sending it.
    #
    # `curl -C -` resumes onto whatever is already at this path, and the path
    # carries the *local* shell's PID -- which repeats across runs. A leftover
    # file from an earlier attempt therefore looks complete: curl resumes at its
    # end, downloads nothing, reports 100% instantly, and the checksum passes
    # because the bytes that are there are genuine. What gets imported is
    # whatever that file actually holds, which may be almost nothing.
    # The `=~ ^[0-9]+$` gate before any arithmetic is the same guard the
    # free-space probe above carries, and for the same reason: `(( ))` expands
    # an array subscript before evaluating it, so a reply of `PATH[$(...)]`
    # from a hostile or impersonated pool master would execute here, on the
    # workstation. Checked as a string first, and only then as a number.
    local staged=""
    staged=$(dom0_exec "stat -c %s '${tmp}' 2>/dev/null" | tr -d '\r')
    local staged_ok=0
    if [[ "$staged" =~ ^[0-9]+$ ]] && (( staged >= 104857600 )); then
        staged_ok=1
    fi
    if (( staged_ok == 0 )); then
        log_error "  the staged image on the pool master is ${staged:-0} bytes."
        log_error "  A stale file at ${tmp} was resumed instead of downloaded."
        log_error "  Remove it on the pool master and run this again:"
        log_error "    ssh ${HOST_USERNAME}@${POOL_MASTER_IP} rm -f '${tmp}'"
        dom0_exec "rm -f '${tmp}'" >/dev/null 2>&1 || true
        return 1
    fi

    log_info "  importing it into the disk..."
    local rc=0 out=""
    # --show-error so a rejected import says why. Without it -s swallows the
    # message and -f reduces an HTTP error to a bare exit code, which leaves
    # the caller guessing at a cause it cannot see.
    local vdi_ref
    if ! vdi_ref=$(deploy_vdi_ref "$vdi"); then
        log_error "  could not resolve the disk ${vdi} to an XAPI reference."
        dom0_exec "rm -f '${tmp}'" >/dev/null 2>&1 || true
        return 1
    fi
    # The task is what turns a silent server-side failure into a message. See
    # deploy_task_check: curl exiting 0 says only that XAPI accepted the body.
    local task
    task=$(deploy_task_create "import ${vdi}")
    local task_q=""
    [[ "$task" =~ ^OpaqueRef: ]] && task_q="&task_id=${task}"

    # -L is load-bearing on a pool with more than one host. XAPI's import
    # handler checks whether the host being asked can actually see the SR, and
    # answers 302 to the host that can when it cannot (import_raw_vdi.ml,
    # `check_sr_availability` / `return_302_redirect`). Without -L, curl treats
    # that 302 as a successful response -- -f only fails on 4xx and 5xx -- so it
    # exits 0 having sent the body nowhere, leaving a VDI with a few kilobytes
    # of header in it. --post301/302/303 keeps the PUT a PUT across the hop.
    # -w records the redirect count so a silently-swallowed hop cannot happen
    # again unnoticed.
    out=$(dom0_exec "curl -sk -f -L --post301 --post302 --post303 --show-error \
        -w '\nxo-redirects=%{num_redirects} xo-code=%{http_code}\n' \
        --speed-limit 1024 --speed-time 60 --max-time 3600 -T '${tmp}' \
        'https://localhost/import_raw_vdi?session_id=${DEPLOY_SESSION}&vdi=${vdi_ref}&format=raw${task_q}' 2>&1") || rc=$?
    local hops
    hops=$(sed -n 's/.*xo-redirects=\([0-9]*\).*/\1/p' <<< "$out" | tail -1)
    if [[ "$hops" =~ ^[0-9]+$ ]] && (( hops > 0 )); then
        log_info "  the pool master redirected the import to the host holding the SR."
    fi
    out=$(grep -v 'xo-redirects=' <<< "$out")
    if (( rc != 0 )) && [[ -n "$out" ]]; then
        log_error "  the pool master rejected the import:"
        printf '%s\n' "$out" | head -5 | while IFS= read -r line; do
            log_error "    ${line}"
        done
    fi
    if (( rc == 0 )) && ! deploy_task_check "$task"; then
        rc=1
    fi
    deploy_task_destroy "$task"
    dom0_exec "rm -f '${tmp}'" >/dev/null 2>&1 || true
    return $rc
}

# Import a local file into a VDI. Used for the cloud-init config drive, which
# is small enough that the extra SSH hop costs nothing. It cannot go in over
# `xe vdi-import` for the same reason the image cannot.
# Arguments: VDI uuid, local file path
deploy_import_vdi_from_file() {
    local vdi="$1" path="$2"
    local remote="/tmp/xo-deploy-cidata-$$.iso"

    dom0_exec "cat > '${remote}'" < "$path" || {
        log_error "Could not copy the config drive to the pool master."
        return 1
    }

    local vdi_ref
    if ! vdi_ref=$(deploy_vdi_ref "$vdi"); then
        log_error "Could not resolve the config drive ${vdi} to an XAPI reference."
        dom0_exec "rm -f '${remote}'" >/dev/null 2>&1 || true
        return 1
    fi

    local task
    task=$(deploy_task_create "import ${vdi}")
    local task_q=""
    [[ "$task" =~ ^OpaqueRef: ]] && task_q="&task_id=${task}"

    local rc=0
    # -L for the same reason as the image import above: on a multi-host pool the
    # SR may not be visible from the master, and an unfollowed 302 sends the
    # config drive nowhere while reporting success.
    dom0_exec "curl -sk -f -L --post301 --post302 --post303 --max-time 300 -T '${remote}' \
        'https://localhost/import_raw_vdi?session_id=${DEPLOY_SESSION}&vdi=${vdi_ref}&format=raw${task_q}'" || rc=$?
    if (( rc == 0 )) && ! deploy_task_check "$task"; then
        rc=1
    fi
    deploy_task_destroy "$task"
    dom0_exec "rm -f '${remote}'" >/dev/null 2>&1 || true
    return $rc
}

# Name the VM left behind when a deploy dies, so it is not left to be
# rediscovered later in the pool's VM list.
#
# Deliberately does not destroy anything: the half-built VM is the operator's
# to remove, and a deploy that just failed is a bad moment for a script to
# start deleting disks on someone's pool. This only makes sure the UUID is the
# last thing on screen rather than something to scroll back for.
deploy_report_failed_vm() {
    [[ "${DEPLOY_SUCCEEDED}" == "true" ]] && return 0
    [[ -n "${DEPLOY_VM_UUID:-}" ]] || return 0

    log_warning "The VM ${DEPLOY_VM_NAME} (${DEPLOY_VM_UUID}) was left on the pool."
    log_warning "Delete it when you are done with it -- a retry with the same name"
    log_warning "will otherwise sit alongside it:"
    log_warning "  xe vm-destroy uuid=${DEPLOY_VM_UUID}"
}

# Deal with a config drive left behind by an aborted deploy.
#
# The drive carries the guest's private key and, when one was set, the admin
# account's password hash — so an abort must not simply walk away from it. What
# it must not do either is destroy a drive the guest may still be reading:
# after vm-start, cloud-init may not have run yet, and the operator is being
# told to go look at the console. So the drive is only removed outright when
# the VM was never started; otherwise the exact removal commands are printed.
deploy_cleanup_config_drive() {
    [[ -n "${DEPLOY_CIDATA_VDI:-}" ]] || return 0

    if [[ "${DEPLOY_VM_STARTED}" != "true" ]]; then
        if [[ -n "${DEPLOY_CIDATA_VBD:-}" ]]; then
            dom0_xe "vbd-destroy uuid=${DEPLOY_CIDATA_VBD}" >/dev/null 2>&1 || true
        fi
        if dom0_xe "vdi-destroy uuid=${DEPLOY_CIDATA_VDI}" >/dev/null 2>&1; then
            log_info "Removed the cloud-init config drive left by the aborted deploy."
            DEPLOY_CIDATA_VDI=""
            DEPLOY_CIDATA_VBD=""
            return 0
        fi
    fi

    log_warning "The cloud-init config drive is still on the pool. It holds the VM's"
    log_warning "SSH key and your admin password hash — remove it once you are done:"
    if [[ -n "${DEPLOY_CIDATA_VBD:-}" ]]; then
        log_warning "  xe vbd-unplug uuid=${DEPLOY_CIDATA_VBD}"
        log_warning "  xe vbd-destroy uuid=${DEPLOY_CIDATA_VBD}"
    fi
    log_warning "  xe vdi-destroy uuid=${DEPLOY_CIDATA_VDI}"
    return 0
}

# Close the shared SSH connection and remove the deploy scratch directory.
# Registered as an EXIT trap by deploy_xo_vm so an abort doesn't leave a live
# master socket, an XAPI session, or a config drive containing an SSH key.
#
# Runs before the SSH connection is torn down, since the config-drive cleanup
# needs `xe` on the pool master.
deploy_cleanup() {
    deploy_cleanup_config_drive
    deploy_report_failed_vm
    deploy_xapi_logout
    if [[ -n "$DEPLOY_SSH_CTL" && -S "$DEPLOY_SSH_CTL" ]]; then
        ssh -o ControlPath="$DEPLOY_SSH_CTL" -O exit \
            "${HOST_USERNAME}@${POOL_MASTER_IP}" 2>/dev/null || true
    fi
    if [[ -n "$DEPLOY_WORKDIR" && -d "$DEPLOY_WORKDIR" ]]; then
        # The deployment key's private half lives here and is never copied out,
        # so this is where it dies. rm alone is enough for a mode-700 directory
        # under /tmp, but shred costs nothing when it is available and closes
        # the gap on filesystems that hand the blocks straight back.
        if [[ -f "${DEPLOY_WORKDIR}/id_ed25519" ]] && command -v shred >/dev/null 2>&1; then
            shred -u "${DEPLOY_WORKDIR}/id_ed25519" 2>/dev/null || true
        fi
        rm -rf "$DEPLOY_WORKDIR"
    fi
}

# Present a numbered list and read a selection.
# Arguments: prompt text, then one "value|label" argument per option.
# Sets DEPLOY_CHOICE to the chosen value.
deploy_choose() {
    local prompt="$1"; shift
    local options=("$@")
    local count=${#options[@]}

    if [[ $count -eq 0 ]]; then
        log_error "No options available for: $prompt"
        exit 1
    fi

    # A single option needs no menu.
    if [[ $count -eq 1 ]]; then
        DEPLOY_CHOICE="${options[0]%%|*}"
        log_info "${prompt}: ${options[0]#*|} (only option)"
        return 0
    fi

    echo ""
    echo "$prompt"
    echo ""
    local i
    for ((i = 0; i < count; i++)); do
        printf "  %2d) %s\n" "$((i + 1))" "${options[$i]#*|}"
    done
    echo ""

    local reply
    while true; do
        echo -n "Pick a number [1-${count}]: "
        read -t 300 -r reply < /dev/tty || { log_error "Input timeout"; exit 1; }
        if [[ "$reply" =~ ^[0-9]+$ ]] && (( reply >= 1 && reply <= count )); then
            DEPLOY_CHOICE="${options[$((reply - 1))]%%|*}"
            return 0
        fi
        log_warning "Enter a number between 1 and ${count}."
    done
}

# Prompt until the answer matches a regex and, optionally, a validator.
#
# Arguments: prompt, regex, default, variable name, [validator function]
#
# The validator exists because a regex can only check shape: it is what stops
# 999.999.999.999 or port 70000 being accepted here and only rejected later,
# after the VM has been created.
deploy_read_validated() {
    local prompt="$1" regex="$2" default="$3" varname="$4" validator="${5:-}"
    local reply
    while true; do
        if [[ -n "$default" ]]; then
            echo -n "${prompt} [${default}]: "
        else
            echo -n "${prompt}: "
        fi
        read -t 300 -r reply < /dev/tty || { log_error "Input timeout"; exit 1; }
        reply="${reply:-$default}"
        if [[ "$reply" =~ $regex ]] && { [[ -z "$validator" ]] || "$validator" "$reply"; }; then
            printf -v "$varname" '%s' "$reply"
            return 0
        fi
        log_warning "Invalid value, please try again."
    done
}

# Convert a dotted-quad netmask to a CIDR prefix length.
# cloud-init's network-config v2 schema takes a prefix, but a netmask is what
# most people know their network by, so we ask for one and convert.
# A mask must also be contiguous — every 1 bit ahead of every 0 bit. Tracking
# that matters: without it 255.0.255.0 would quietly convert to /16 and the
# guest would come up on the wrong subnet.
netmask_to_prefix() {
    local mask="$1"
    local octet bits=0 ended=0
    local IFS='.'
    for octet in $mask; do
        local add
        case "$octet" in
            255) add=8 ;;
            254) add=7 ;;
            252) add=6 ;;
            248) add=5 ;;
            240) add=4 ;;
            224) add=3 ;;
            192) add=2 ;;
            128) add=1 ;;
            0)   add=0 ;;
            *)   echo ""; return 1 ;;
        esac

        # Nothing but zeroes may follow the first non-full octet.
        if (( ended == 1 && add != 0 )); then
            echo ""
            return 1
        fi
        (( add < 8 )) && ended=1

        bits=$((bits + add))
    done
    echo "$bits"
}

# Verify the tools --deploy needs locally, installing the ones we can.
# Note this is the *workstation's* dependency list — it is deliberately short,
# because all the XAPI work happens on the pool master.
deploy_check_local_deps() {
    # An ISO9660 writer is the one thing we may genuinely have to install, for
    # the cloud-init config drive. Either tool will do and most systems already
    # have one; xorriso is packaged on both Debian and RHEL families, so that
    # is what we reach for when neither is present.
    #
    # sudo is requested here rather than up front in main(): --deploy changes
    # nothing on this machine, so asking for a password before we know we need
    # one is pure friction.
    if ! command -v genisoimage >/dev/null 2>&1 && ! command -v xorriso >/dev/null 2>&1; then
        log_info "The cloud-init config drive needs an ISO writer, which is not installed."
        detect_package_manager
        check_sudo
        log_info "Installing xorriso..."
        pkg_update_soft
        # shellcheck disable=SC2086
        if ! run_cmd $PKG_INSTALL xorriso; then
            log_error "Could not install xorriso."
            log_error "Install an ISO9660 writer yourself and rerun --deploy:"
            log_error "  Debian/Ubuntu: sudo apt-get install xorriso"
            log_error "  RHEL family:   sudo dnf install xorriso"
            exit 1
        fi
    fi

    local missing=()
    for cmd in ssh scp ssh-keygen ssh-keyscan; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing[*]}"
        log_error "Install your distribution's openssh-client package and retry."
        exit 1
    fi
}

# Show the pool master's SSH host key the first time we see it.
#
# Every dom0_exec after this carries the host's root password, so the very
# first connection is the one that matters: ssh rejects a *changed* key on its
# own, but on first contact there is nothing to compare against, and anything
# answering on that address would collect the password. Once the key is in
# known_hosts, ssh enforces it and this is a no-op.
#
# Set XO_DEPLOY_POOL_FINGERPRINT to the expected SHA256 fingerprint to check it
# without a prompt -- the only form of this that works under --non-interactive.

# Pin the scanned host key so dom0_exec is bound to the key that was verified.
#
# Every line of the scan is pinned, not just the ED25519 one whose fingerprint
# was displayed: the host legitimately offers several types and ssh picks one at
# negotiation time. Pinning the whole scan means whichever it picks came from
# the host we checked, while a key that was not in the scan -- an attacker's RSA
# key offered in place of the ED25519 one we showed the operator -- is rejected
# outright rather than accepted under `accept-new`.
deploy_pin_pool_host_key() {
    local scan="$1"
    local pinned="${DEPLOY_WORKDIR}/pool_known_hosts"

    cp "$scan" "$pinned" 2>/dev/null || return 0
    chmod 600 "$pinned" 2>/dev/null || true
    DEPLOY_POOL_KNOWN_HOSTS="$pinned"
}

deploy_verify_host_key() {
    local expected="${XO_DEPLOY_POOL_FINGERPRINT:-}"

    if ssh-keygen -F "$POOL_MASTER_IP" >/dev/null 2>&1; then
        [[ -n "$expected" ]] || return 0
    fi

    local scan="${DEPLOY_WORKDIR}/pool_hostkey"
    if ! ssh-keyscan -T 10 "$POOL_MASTER_IP" > "$scan" 2>/dev/null || [[ ! -s "$scan" ]]; then
        # A pinned fingerprint is an explicit request for enforcement, so a scan
        # that did not happen is a failure, not a warning. Returning 0 here would
        # hand the password to whatever answers on that address -- which is the
        # one outcome pinning exists to prevent, and the easiest for an on-path
        # attacker to arrange: drop the probe for ten seconds, then answer the
        # real connection.
        if [[ -n "$expected" ]]; then
            log_error "Could not read the SSH host key of ${POOL_MASTER_IP}."
            log_error "XO_DEPLOY_POOL_FINGERPRINT is set, so it cannot be checked and"
            log_error "the host password will not be sent. Confirm the host is reachable"
            log_error "on port 22 and retry."
            exit 1
        fi
        log_warning "Could not read the SSH host key of ${POOL_MASTER_IP} in advance."
        log_warning "ssh accepts an unknown key on first contact, so it will NOT be"
        log_warning "verified for you. Set XO_DEPLOY_POOL_FINGERPRINT to have it checked."
        return 0
    fi

    # Prefer the ed25519 key when the host offers several, so the fingerprint
    # shown is the same one on every run rather than whichever ssh-keyscan
    # happened to return first.
    local fp_line
    fp_line=$(ssh-keygen -lf "$scan" 2>/dev/null | grep -i 'ED25519' | head -1)
    [[ -n "$fp_line" ]] || fp_line=$(ssh-keygen -lf "$scan" 2>/dev/null | head -1)
    if [[ -z "$fp_line" ]]; then
        # Same reasoning as above: with a pin set, "could not check" is a refusal.
        if [[ -n "$expected" ]]; then
            log_error "Could not fingerprint the host key of ${POOL_MASTER_IP}, so the"
            log_error "XO_DEPLOY_POOL_FINGERPRINT check cannot be made. Refusing to send"
            log_error "the host password."
            exit 1
        fi
        log_warning "Could not fingerprint the host key of ${POOL_MASTER_IP}; continuing."
        return 0
    fi

    local fp
    fp=$(awk '{print $2}' <<< "$fp_line")

    if [[ -n "$expected" ]]; then
        if [[ "$fp" == "$expected" ]]; then
            deploy_pin_pool_host_key "$scan"
            log_success "Pool master host key matches XO_DEPLOY_POOL_FINGERPRINT."
            return 0
        fi
        log_error "The host key of ${POOL_MASTER_IP} does not match XO_DEPLOY_POOL_FINGERPRINT."
        log_error "  expected: ${expected}"
        log_error "  offered:  ${fp}"
        log_error "Refusing to send the host password. Investigate before retrying."
        exit 1
    fi

    echo ""
    log_warning "First connection to ${POOL_MASTER_IP} — its SSH host key is not known yet."
    echo ""
    echo "  ${fp_line}"
    echo ""
    echo "  The host password you just entered is sent over this connection, so it is"
    echo "  worth one check. On the pool master's console, run:"
    echo ""
    echo "    ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
    echo ""
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        # Still pinned: nobody confirmed this key, but binding the run to the one
        # key we saw is strictly better than letting every later connection take
        # whatever is offered.
        deploy_pin_pool_host_key "$scan"
        log_warning "Non-interactive: accepting this key without confirmation."
        log_warning "Set XO_DEPLOY_POOL_FINGERPRINT to have it verified instead."
        return 0
    fi
    if ! confirm_or_skip "Does that fingerprint match?"; then
        log_error "Host key not confirmed. Nothing has been sent to ${POOL_MASTER_IP}."
        exit 1
    fi

    deploy_pin_pool_host_key "$scan"
}

# Collect pool master connection details and open the shared SSH connection.
deploy_connect_pool_master() {
    # HOST_PASSWORD is read here and used by every dom0_exec from here on, so
    # tracing stays off for the whole function rather than being flipped back
    # on immediately after the read. See the note above dom0_exec.
    local -
    set +x

    echo ""
    echo "=============================================="
    echo "  Pool Master Connection"
    echo "=============================================="
    echo ""
    echo "The VM is created on this host. You need its IP and root credentials."
    echo ""

    deploy_read_validated "IP address or hostname of the pool master" \
        '^[A-Za-z0-9._-]+$' "" POOL_MASTER_IP

    deploy_read_validated "Host username" '^[a-z_][a-z0-9_-]*$' "root" HOST_USERNAME

    echo -n "Host password: "
    read -rs HOST_PASSWORD < /dev/tty
    echo ""
    if [[ -z "$HOST_PASSWORD" ]]; then
        log_error "Host password is required"
        exit 1
    fi

    DEPLOY_SSH_CTL="${DEPLOY_WORKDIR}/ssh-ctl"

    # The password is needed either way: XAPI's HTTP endpoint authenticates
    # with it, not with an SSH key. sshpass just saves ssh asking again.
    if command -v sshpass >/dev/null 2>&1; then
        DEPLOY_AUTH_MODE="sshpass"
    else
        DEPLOY_AUTH_MODE="prompt"
        echo ""
        log_info "sshpass is not installed, so ssh will ask for that password once more."
        log_info "Installing sshpass avoids the second prompt; nothing else changes."
    fi

    deploy_verify_host_key

    log_info "Connecting to ${HOST_USERNAME}@${POOL_MASTER_IP}..."
    # Not redirected: in prompt mode this is where ssh asks for the password,
    # and hiding its prompt would look like a hang.
    if ! dom0_exec "true"; then
        log_error "Could not connect to the pool master. Check the address and credentials."
        exit 1
    fi

    # Confirm this is actually a XenServer/XCP-ng host before going further —
    # a friendly failure here beats a confusing one three prompts later.
    if ! dom0_exec "command -v xe" >/dev/null 2>&1; then
        log_error "'xe' was not found on ${POOL_MASTER_IP}."
        log_error "--deploy must point at a XenServer/XCP-ng host, not the machine XO will run on."
        exit 1
    fi

    local host_desc
    host_desc=$(dom0_xe "host-list params=name-label --minimal" 2>/dev/null || echo "")
    log_success "Connected to pool master${host_desc:+ (${host_desc})}"

    # Disk imports go through XAPI's HTTP endpoint, which needs a session.
    # Do it now so a bad password fails here rather than after the VM exists.
    deploy_xapi_login
    log_success "Authenticated to XAPI"
}

# Choose the storage repository for the VM's disks.
deploy_pick_sr() {
    local raw
    # One round trip: enumerate user SRs and print "uuid|label (free space)".
    raw=$(dom0_exec 'for u in $(xe sr-list content-type=user params=uuid --minimal | tr "," " "); do
            name=$(xe sr-param-get uuid=$u param-name=name-label 2>/dev/null)
            size=$(xe sr-param-get uuid=$u param-name=physical-size 2>/dev/null)
            used=$(xe sr-param-get uuid=$u param-name=physical-utilisation 2>/dev/null)
            free=$(( (size - used) / 1073741824 ))
            echo "$u|$name (${free} GiB free)"
        done' | tr -d '\r')

    local options=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && options+=("$line")
    done <<< "$raw"

    if [[ ${#options[@]} -eq 0 ]]; then
        log_error "No usable storage repositories found on this pool."
        log_error "Create an SR first: https://xcp-ng.org/docs/storage.html"
        exit 1
    fi

    deploy_choose "Which storage repository should hold the VM's disks?" "${options[@]}"
    DEPLOY_SR_UUID="$DEPLOY_CHOICE"
}

# Choose the network the VM's interface attaches to.
deploy_pick_network() {
    local raw
    raw=$(dom0_exec 'for u in $(xe network-list params=uuid --minimal | tr "," " "); do
            name=$(xe network-param-get uuid=$u param-name=name-label 2>/dev/null)
            desc=$(xe network-param-get uuid=$u param-name=name-description 2>/dev/null)
            echo "$u|$name${desc:+ — $desc}"
        done' | tr -d '\r')

    local options=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && options+=("$line")
    done <<< "$raw"

    if [[ ${#options[@]} -eq 0 ]]; then
        log_error "No networks found on this pool."
        exit 1
    fi

    deploy_choose "Which network should the VM use?" "${options[@]}"
    DEPLOY_NETWORK_UUID="$DEPLOY_CHOICE"
}

# Collect VM sizing and guest OS settings.
deploy_prompt_vm_specs() {
    echo ""
    echo "=============================================="
    echo "  VM Configuration"
    echo "=============================================="
    echo ""

    deploy_read_validated "VM name" '^[A-Za-z0-9][A-Za-z0-9._-]*$' "xen-orchestra" DEPLOY_VM_NAME
    deploy_read_validated "Hostname for the guest" '^[a-z0-9][a-z0-9-]*$' "xen-orchestra" DEPLOY_HOSTNAME
    deploy_read_validated "vCPUs" '^[1-9][0-9]*$' "2" DEPLOY_VCPUS
    deploy_read_validated "Memory in GB (XO needs 4 GB or more)" '^[1-9][0-9]*$' "4" DEPLOY_RAM_GB

    while true; do
        deploy_read_validated "Disk size in GB" '^[1-9][0-9]*$' "20" DEPLOY_DISK_GB
        if (( DEPLOY_DISK_GB >= XO_DEPLOY_MIN_DISK_GB )); then
            break
        fi
        log_warning "Disk must be at least ${XO_DEPLOY_MIN_DISK_GB} GB (the cloud image alone is 3 GB)."
    done

    if (( DEPLOY_RAM_GB < 4 )); then
        log_warning "Xen Orchestra builds from source and may fail to build with under 4 GB."
    fi

    deploy_read_validated "Admin username for the VM (used for SSH)" \
        '^[a-z_][a-z0-9_-]*$' "xo" DEPLOY_ADMIN_USER

    deploy_prompt_admin_password
    deploy_prompt_admin_ssh_key
    deploy_prompt_repo_dir
}

# Read and validate an SSH public key, echoing the single line to install.
#
# Takes a file path or the key text itself. Two checks, because either alone
# lets something through that matters here:
#
#   - the first field must be a known public key type, which is what stops a
#     *private* key being accepted. `ssh-keygen -l` happily fingerprints a
#     private key file, and the key ends up in cloud-init's user-data, which is
#     world-readable inside the guest -- the exact leak this whole change is
#     about;
#   - ssh-keygen must then agree it parses, which catches truncation and the
#     line-wrapping that copying a key through a chat window introduces.
#
# Returns 1 and echoes nothing when the input is not a usable public key.
deploy_load_pubkey() {
    local src="$1" line=""

    if [[ -f "$src" ]]; then
        line=$(head -1 "$src" 2>/dev/null) || return 1
    else
        line="$src"
    fi

    # Strip a trailing CR from a key that has been through a Windows editor,
    # plus surrounding whitespace.
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"

    [[ -n "$line" ]] || return 1

    # ssh-dss is deliberately absent. DSA is capped at 1024 bits, OpenSSH has
    # refused it since 7.0 and dropped the code entirely in 9.8, so accepting
    # one here would not grant access -- it would install a key that silently
    # never works and send the operator hunting for the reason.
    case "${line%% *}" in
        ssh-ed25519|ssh-rsa| \
        ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521| \
        sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) ;;
        *) return 1 ;;
    esac

    local check="${DEPLOY_WORKDIR}/pubkey.check"
    printf '%s\n' "$line" > "$check"
    if ! ssh-keygen -l -f "$check" >/dev/null 2>&1; then
        rm -f "$check"
        return 1
    fi
    rm -f "$check"

    printf '%s' "$line"
}

# Describe a public key for a prompt or the summary: "ed25519 SHA256:... (comment)".
deploy_pubkey_label() {
    local line="$1" check="${DEPLOY_WORKDIR}/pubkey.label" out=""
    printf '%s\n' "$line" > "$check"
    out=$(ssh-keygen -l -f "$check" 2>/dev/null || true)
    rm -f "$check"
    if [[ -n "$out" ]]; then
        # ssh-keygen prints "<bits> <fingerprint> <comment> (<TYPE>)".
        printf '%s' "$out"
    else
        printf '%s' "${line%% *}"
    fi
}

# Hash a password for cloud-init's hashed_passwd, printing the crypt string.
# SHA-512 ($6$) is what both tools below produce and what Debian expects.
# The password is fed over stdin so it never appears in the process list.
deploy_hash_password() {
    local -
    set +x

    local pw="$1" hash=""

    if command -v openssl >/dev/null 2>&1; then
        # -6 needs OpenSSL 1.1.1 or newer; older builds fail and fall through.
        hash=$(printf '%s' "$pw" | openssl passwd -6 -stdin 2>/dev/null) || hash=""
    fi
    if [[ -z "$hash" ]] && command -v mkpasswd >/dev/null 2>&1; then
        hash=$(printf '%s\n' "$pw" | mkpasswd -m sha-512 --stdin 2>/dev/null) || hash=""
    fi

    [[ -n "$hash" ]] || return 1
    printf '%s' "$hash"
}

# Optionally set a password on the guest's admin account.
#
# The password is required, not optional. The keypair this script generates is
# a deployment credential that deploy_revoke_deploy_key destroys when the
# install finishes, so the password is what remains: it is the console login on
# the XCP-ng/XenServer console where no key can be offered, what `su` asks for,
# and what sudo asks for once deploy_harden_guest_sudo has run. An account
# without one would be unreachable the moment the deploy key goes away.
deploy_prompt_admin_password() {
    # The console password is compared and hashed in here, both of which xtrace
    # would print. See the note above dom0_exec for why `local -` is enough.
    local -
    set +x

    DEPLOY_ADMIN_PASSWORD_HASH=""
    DEPLOY_ADMIN_SSH_PWAUTH="false"

    # Hashing is mandatory now, so a missing tool is a hard failure rather than
    # the quiet downgrade to a key-only account this used to be.
    if ! command -v openssl >/dev/null 2>&1 && ! command -v mkpasswd >/dev/null 2>&1; then
        log_error "The admin account needs a password, and hashing one needs openssl"
        log_error "or mkpasswd. Neither is installed."
        log_error "  Debian/Ubuntu: sudo apt-get install openssl"
        log_error "  RHEL family:   sudo dnf install openssl"
        exit 1
    fi

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if [[ -z "${XO_DEPLOY_ADMIN_PASSWORD:-}" ]]; then
            log_error "A password for ${DEPLOY_ADMIN_USER} is required, and there is no terminal"
            log_error "to ask for one. Set XO_DEPLOY_ADMIN_PASSWORD and retry."
            exit 1
        fi
        if (( ${#XO_DEPLOY_ADMIN_PASSWORD} < XO_DEPLOY_MIN_PASSWORD_LEN )); then
            log_error "XO_DEPLOY_ADMIN_PASSWORD is shorter than ${XO_DEPLOY_MIN_PASSWORD_LEN} characters."
            exit 1
        fi
        if ! DEPLOY_ADMIN_PASSWORD_HASH=$(deploy_hash_password "$XO_DEPLOY_ADMIN_PASSWORD"); then
            log_error "Could not hash XO_DEPLOY_ADMIN_PASSWORD with openssl or mkpasswd."
            exit 1
        fi
        if [[ "${XO_DEPLOY_ADMIN_SSH_PWAUTH:-false}" == "true" ]]; then
            DEPLOY_ADMIN_SSH_PWAUTH="true"
        fi
        log_info "Non-interactive: admin password taken from XO_DEPLOY_ADMIN_PASSWORD."
        return 0
    fi

    echo ""
    echo "The ${DEPLOY_ADMIN_USER} account needs a password. This is not optional:"
    echo ""
    echo "  - it is the only way in on the VM's console, where no SSH key can be offered;"
    echo "  - sudo asks for it once the install finishes and the passwordless rule the"
    echo "    unattended install needed is revoked;"
    echo "  - the SSH key this script generates is a deployment credential and is"
    echo "    destroyed when the deploy finishes, so it will not be there for you."
    echo ""
    echo "Minimum ${XO_DEPLOY_MIN_PASSWORD_LEN} characters. Use a password manager."
    echo ""

    local pw1 pw2
    while true; do
        read -t 300 -rsp "Password for ${DEPLOY_ADMIN_USER}: " pw1 < /dev/tty \
            || { log_error "Input timeout"; exit 1; }
        echo ""

        if (( ${#pw1} < XO_DEPLOY_MIN_PASSWORD_LEN )); then
            log_warning "Use at least ${XO_DEPLOY_MIN_PASSWORD_LEN} characters."
            continue
        fi

        read -t 300 -rsp "Confirm password: " pw2 < /dev/tty \
            || { log_error "Input timeout"; exit 1; }
        echo ""
        if [[ "$pw1" != "$pw2" ]]; then
            log_warning "Passwords do not match, please try again."
            continue
        fi
        break
    done

    if ! DEPLOY_ADMIN_PASSWORD_HASH=$(deploy_hash_password "$pw1"); then
        log_error "Could not hash the password with openssl or mkpasswd."
        exit 1
    fi
    pw1=""; pw2=""

    if confirm_or_skip "Also allow SSH logins with this password?"; then
        DEPLOY_ADMIN_SSH_PWAUTH="true"
    else
        log_info "SSH stays key-only; the password is for the console, su and sudo."
    fi
}

# Ask for a public key to install on the admin account.
#
# The keypair this script generates exists so the unattended install can run,
# and deploy_revoke_deploy_key removes it from the VM when that is done -- it
# is never saved to disk for you to look after, because an unencrypted private
# key granting root-equivalent access is exactly the credential an audit picks
# up on. Anything you want to keep using has to be your own key, so this asks
# for one instead of handing you ours.
#
# Declining is fine: the account still has its password for the console, and
# for SSH too if you enabled password logins.
deploy_prompt_admin_ssh_key() {
    DEPLOY_USER_PUBKEY=""

    local candidate=""

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        candidate="${XO_DEPLOY_ADMIN_SSH_KEY:-}"
        if [[ -z "$candidate" ]]; then
            log_info "Non-interactive: no XO_DEPLOY_ADMIN_SSH_KEY set."
            log_warning "The VM will have no SSH key. Console access uses the admin password."
            return 0
        fi
        if ! DEPLOY_USER_PUBKEY=$(deploy_load_pubkey "$candidate"); then
            log_error "XO_DEPLOY_ADMIN_SSH_KEY is not a usable SSH public key: ${candidate}"
            exit 1
        fi
        log_info "Installing the public key from XO_DEPLOY_ADMIN_SSH_KEY."
        return 0
    fi

    # Offer the operator's own key rather than making them type a path.
    local default="" f
    for f in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_ecdsa.pub" "$HOME/.ssh/id_rsa.pub"; do
        if [[ -r "$f" ]]; then default="$f"; break; fi
    done

    echo ""
    echo "SSH access to the finished VM uses a key you own."
    echo ""
    echo "The key this script generates for the install is destroyed at the end of the"
    echo "deploy, so it will not be left on your disk and cannot be used afterwards."
    echo "Give a public key here to keep SSH access; leave it empty for console-only."
    echo ""

    local reply
    while true; do
        if [[ -n "$default" ]]; then
            echo -n "Public key file to install [${default}] (empty for none): "
        else
            echo -n "Public key file to install (empty for none): "
        fi
        read -t 300 -r reply < /dev/tty || { log_error "Input timeout"; exit 1; }

        # A bare Enter takes the offered default when there is one; "-" is the
        # escape hatch for wanting no key at all despite having one on disk.
        if [[ -z "$reply" && -n "$default" ]]; then
            reply="$default"
        elif [[ "$reply" == "-" ]]; then
            reply=""
        fi

        if [[ -z "$reply" ]]; then
            log_warning "No SSH key will be installed. Console access uses the admin password."
            if [[ "$DEPLOY_ADMIN_SSH_PWAUTH" != "true" ]]; then
                log_warning "SSH password logins are off, so the console is the only way in."
            fi
            confirm_or_skip "Continue without an SSH key?" && return 0
            continue
        fi

        # `read` does not do tilde expansion, so a path typed as ~/.ssh/id.pub
        # arrives with a literal tilde and would not be found. The quoted "~/"
        # below is deliberately literal -- it is the text being matched, not a
        # path being expanded.
        # shellcheck disable=SC2088
        if [[ "$reply" == "~/"* ]]; then
            reply="${HOME}/${reply#\~/}"
        fi

        if DEPLOY_USER_PUBKEY=$(deploy_load_pubkey "$reply"); then
            log_success "Will install: $(deploy_pubkey_label "$DEPLOY_USER_PUBKEY")"
            return 0
        fi
        log_warning "That is not a usable SSH public key file. Try again, or empty for none."
    done
}

# Ask where the repo should be cloned inside the VM.
#
# /opt keeps it out of the admin's home directory (and survives that user being
# removed); the home directory keeps everything under one owner and needs no
# root privileges to edit afterwards.
deploy_prompt_repo_dir() {
    local home_dir="/home/${DEPLOY_ADMIN_USER}/install_xen_orchestra"

    deploy_choose "Where should this repo be cloned inside the VM?" \
        "/opt/install_xen_orchestra|/opt/install_xen_orchestra (system-wide)" \
        "${home_dir}|${home_dir} (${DEPLOY_ADMIN_USER}'s home directory)"
    DEPLOY_REPO_DIR="$DEPLOY_CHOICE"
}

# Collect the guest's static network settings.
#
# A static address is required rather than merely offered: a stock Debian cloud
# image has no xe-guest-utilities, so the host cannot report a DHCP-assigned
# address back to us and we would have no way to reach the VM afterwards.
deploy_prompt_network_settings() {
    local ipregex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    echo ""
    echo "=============================================="
    echo "  Guest Network Settings"
    echo "=============================================="
    echo ""
    echo "A static address is required. The Debian cloud image ships without"
    echo "xen-guest-utilities, so the host cannot report a DHCP lease back and"
    echo "this script would have no address to install over."
    echo ""

    deploy_read_validated "IP address for the VM" "$ipregex" "" DEPLOY_IP is_ipv4
    deploy_read_validated "Netmask" "$ipregex" "255.255.255.0" DEPLOY_NETMASK is_ipv4
    deploy_read_validated "Gateway" "$ipregex" "" DEPLOY_GATEWAY is_ipv4
    deploy_read_validated "DNS server" "$ipregex" "1.1.1.1" DEPLOY_DNS is_ipv4

    DEPLOY_PREFIX=$(netmask_to_prefix "$DEPLOY_NETMASK")
    if [[ -z "$DEPLOY_PREFIX" ]]; then
        log_error "Netmask ${DEPLOY_NETMASK} is not a valid contiguous subnet mask."
        exit 1
    fi
}

# Read one KEY=value out of a config file without sourcing it, so a base
# config can be inspected before we commit to using it.
deploy_config_value() {
    local file="$1" key="$2" value
    [[ -f "$file" ]] || return 0
    value=$(grep -E "^${key}=" "$file" 2>/dev/null | tail -1 | cut -d= -f2-) || return 0
    # Strip surrounding quotes and any trailing inline comment.
    value="${value%%#*}"
    value="${value%"${value##*[![:space:]]}"}"
    value="${value#[\"\']}"
    value="${value%[\"\']}"
    printf '%s' "$value"
}

# Collect the Xen Orchestra settings that go into the VM's xo-config.cfg.
#
# Only the handful worth asking about at deploy time are prompted for; the rest
# come from the base config chosen here. That base is the repo's sample unless
# you already keep a tuned xo-config.cfg beside the script, in which case you
# are asked which one the VM should start from.
deploy_prompt_xo_settings() {
    DEPLOY_CONFIG_BASE="$SAMPLE_CONFIG"
    DEPLOY_CONFIG_BASE_LABEL="sample-xo-config.cfg (defaults)"

    # Ports and branch are settings, and settings live in the config file. They
    # used to be prompted for here as well, which meant answering questions the
    # chosen file had already answered. They are read from it now instead --
    # override them by editing the config, same as every other setting.
    if [[ -f "$CONFIG_FILE" && "$NON_INTERACTIVE" != "true" ]]; then
        echo ""
        echo "=============================================="
        echo "  Xen Orchestra Settings"
        echo "=============================================="
        echo ""
        echo "You have an xo-config.cfg on this machine. The VM can start from it"
        echo "instead of the sample — check that its paths and users suit a fresh"
        echo "Debian VM, since they were written for wherever it came from."
        echo ""
        if prompt_yes_no "Build the VM from your xo-config.cfg?"; then
            DEPLOY_CONFIG_BASE="$CONFIG_FILE"
            DEPLOY_CONFIG_BASE_LABEL="xo-config.cfg (this machine's settings)"
        fi
    fi

    local http https branch
    http=$(deploy_config_value "$DEPLOY_CONFIG_BASE" HTTP_PORT)
    https=$(deploy_config_value "$DEPLOY_CONFIG_BASE" HTTPS_PORT)
    branch=$(deploy_config_value "$DEPLOY_CONFIG_BASE" GIT_BRANCH)

    # A key the file does not carry falls back to the same default the sample
    # ships, so a trimmed-down config still deploys.
    DEPLOY_HTTP_PORT="${http:-80}"
    DEPLOY_HTTPS_PORT="${https:-443}"
    DEPLOY_GIT_BRANCH="${branch:-master}"

    # Nothing prompts for these any more, so a bad value in the file would
    # otherwise surface as a failed install inside the VM.
    local bad=()
    is_port "$DEPLOY_HTTP_PORT"  || bad+=("HTTP_PORT=${DEPLOY_HTTP_PORT} (must be 1-65535)")
    is_port "$DEPLOY_HTTPS_PORT" || bad+=("HTTPS_PORT=${DEPLOY_HTTPS_PORT} (must be 1-65535)")
    [[ "$DEPLOY_GIT_BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || bad+=("GIT_BRANCH=${DEPLOY_GIT_BRANCH}")

    if [[ ${#bad[@]} -gt 0 ]]; then
        log_error "${DEPLOY_CONFIG_BASE_LABEL} has values the install would choke on:"
        local b
        for b in "${bad[@]}"; do
            log_error "  ${b}"
        done
        log_error "Fix them in $(basename "$DEPLOY_CONFIG_BASE") and run --deploy again."
        exit 1
    fi
}

# Write the cloud-init config drive.
#
# NoCloud looks for a filesystem labelled `cidata` holding user-data and
# meta-data (plus optional network-config), which is why the volume ID below
# matters more than the filename. The drive only has to bring the machine to
# the point where we can SSH in — the actual XO install runs afterwards over
# SSH so its output and error handling reach your terminal instead of
# disappearing into the guest's cloud-init log.
deploy_build_config_drive() {
    # Builds the password_lines block from DEPLOY_ADMIN_PASSWORD_HASH, and the
    # assignment -- unlike the heredoc it feeds -- is expanded by xtrace. Off for
    # the whole function rather than the one line, since everything here is
    # assembling the credential material the guest boots with. See dom0_exec.
    local -
    set +x

    local dir="${DEPLOY_WORKDIR}/cidata"
    mkdir -p "$dir"

    # A throwaway credential for the install itself. It never leaves
    # DEPLOY_WORKDIR (removed by the EXIT trap), and deploy_revoke_deploy_key
    # takes its public half back out of the guest when the install finishes,
    # so it is dead by the time the deploy is over.
    log_info "Generating a temporary SSH keypair for the install..."
    ssh-keygen -t ed25519 -N "" -C "install-xen-orchestra deploy (temporary)" \
        -f "${DEPLOY_WORKDIR}/id_ed25519" >/dev/null
    DEPLOY_SSH_KEY="${DEPLOY_WORKDIR}/id_ed25519"

    DEPLOY_PUBKEY=$(<"${DEPLOY_SSH_KEY}.pub")
    DEPLOY_PUBKEY="${DEPLOY_PUBKEY%$'\n'}"

    # The operator's own key, when they gave one, goes in alongside it and is
    # what remains after the deploy key is revoked.
    local pubkey_lines="      - ${DEPLOY_PUBKEY}"
    if [[ -n "${DEPLOY_USER_PUBKEY:-}" ]]; then
        pubkey_lines="${pubkey_lines}
      - ${DEPLOY_USER_PUBKEY}"
    fi

    cat > "${dir}/meta-data" <<EOF
instance-id: ${DEPLOY_VM_NAME}-$(date +%s)
local-hostname: ${DEPLOY_HOSTNAME}
EOF

    # Match on any interface whose name starts with "e" rather than naming one:
    # the guest may see eth0 or enX0 depending on kernel and udev version.
    cat > "${dir}/network-config" <<EOF
version: 2
ethernets:
  primary:
    match:
      name: "e*"
    dhcp4: false
    addresses:
      - ${DEPLOY_IP}/${DEPLOY_PREFIX}
    routes:
      - to: default
        via: ${DEPLOY_GATEWAY}
    nameservers:
      addresses:
        - ${DEPLOY_DNS}
EOF

    # The account's password lines, built here because an unset password and a
    # set one need different keys. chpasswd/expire keeps the guest from
    # demanding a password change on the first console login.
    local password_lines="    lock_passwd: true" expire_lines=""
    if [[ -n "${DEPLOY_ADMIN_PASSWORD_HASH:-}" ]]; then
        password_lines="    lock_passwd: false
    hashed_passwd: '${DEPLOY_ADMIN_PASSWORD_HASH}'"
        expire_lines="chpasswd:
  expire: false
"
    fi

    # Passwordless sudo is a requirement of the install, not a convenience:
    # check_sudo and --non-interactive both need it for the unattended run
    # below, which happens over SSH with no TTY to answer a password prompt.
    #
    # It is also temporary. deploy_harden_guest_sudo tightens this rule to
    # "ALL=(ALL:ALL) ALL" once the install returns, so the finished VM asks for
    # a password like any other machine. That step needs a password to ask for,
    # so it only runs when the admin account has one -- see the note there.
    #
    # package_upgrade brings the image up to its distribution's current
    # security patches before anything is exposed; the stock cloud image is
    # only patched to its build date. unattended-upgrades keeps it that way,
    # configured explicitly below rather than left to debconf defaults.
    cat > "${dir}/user-data" <<EOF
#cloud-config
hostname: ${DEPLOY_HOSTNAME}
manage_etc_hosts: true
preserve_hostname: false

users:
  - name: ${DEPLOY_ADMIN_USER}
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
${password_lines}
    ssh_authorized_keys:
${pubkey_lines}

${expire_lines}ssh_pwauth: ${DEPLOY_ADMIN_SSH_PWAUTH:-false}
disable_root: true

package_update: true
package_upgrade: true
packages:
  - git
  - curl
  - sudo
  - ca-certificates
  - unattended-upgrades

write_files:
  - path: /etc/apt/apt.conf.d/20auto-upgrades
    permissions: '0644'
    content: |
      APT::Periodic::Update-Package-Lists "1";
      APT::Periodic::Unattended-Upgrade "1";

runcmd:
  - [git, clone, "${DEPLOY_REPO_URL}", "${DEPLOY_REPO_DIR}"]
  - [chown, -R, "${DEPLOY_ADMIN_USER}:${DEPLOY_ADMIN_USER}", "${DEPLOY_REPO_DIR}"]
EOF

    log_info "Building the cloud-init config drive..."
    local iso="${DEPLOY_WORKDIR}/cidata.iso"
    if command -v genisoimage >/dev/null 2>&1; then
        genisoimage -quiet -output "$iso" -volid cidata -joliet -rock \
            "${dir}/user-data" "${dir}/meta-data" "${dir}/network-config"
    else
        xorriso -as mkisofs -quiet -o "$iso" -V cidata -J -r \
            "${dir}/user-data" "${dir}/meta-data" "${dir}/network-config"
    fi

    DEPLOY_CIDATA_ISO="$iso"
    log_success "Config drive built"
}

# Set KEY=value in a config file, appending the line when the key is absent.
#
# A plain `sed s|^KEY=.*|` silently does nothing for a key the base config never
# had — and a missing key is perfectly legal, because load_config supplies a
# default for every one of them. The prompted answer would then vanish and the
# guest would install with that default while the review screen showed the
# value you typed.
deploy_set_config_key() {
    local file="$1" key="$2" value="$3"

    if grep -qE "^${key}=" "$file"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$file"
    else
        printf '%s=%s\n' "$key" "$value" >> "$file"
    fi
}

# Generate the xo-config.cfg the VM will be installed with, starting from the
# sample so every default and explanatory comment carries over, then applying
# the answers collected above.
deploy_build_xo_config() {
    local out="${DEPLOY_WORKDIR}/xo-config.cfg"
    local base="${DEPLOY_CONFIG_BASE:-$SAMPLE_CONFIG}"

    if [[ ! -f "$base" ]]; then
        log_error "Base config not found at ${base}"
        exit 1
    fi

    # A straight copy. No key is rewritten on the way through: singling out
    # three of them was arbitrary, and left every other setting in the file --
    # SERVICE_USER, INSTALL_DIR, NODE_VERSION, BIND_ADDRESS and the rest --
    # being carried across untouched anyway. The VM gets the config as written.
    cp "$base" "$out"

    DEPLOY_XO_CONFIG="$out"
}

# Offer to open the generated config before anything is created on the pool.
#
# This is the only chance to set the options --deploy does not prompt for --
# INSTALL_DIR, SERVICE_USER, NODE_VERSION, backup and SSL paths -- without
# editing the repo's tracked sample. Editing happens on a throwaway copy in
# the work dir, so neither the sample nor your own xo-config.cfg is touched.
deploy_edit_xo_config() {
    [[ "$NON_INTERACTIVE" == "true" ]] && return 0

    echo ""
    echo "The VM's xo-config.cfg is built from ${DEPLOY_CONFIG_BASE_LABEL}."
    echo ""

    confirm_or_skip "Review it in an editor before the VM is created?" || return 0

    # Prefer whatever the user actually uses; PREFERRED_EDITOR is the config's
    # own answer to the same question. Nothing is installed for this -- deploy
    # changes as little as possible on the workstation.
    local editor="${VISUAL:-${EDITOR:-}}"
    if [[ -z "$editor" ]]; then
        editor=$(deploy_config_value "$DEPLOY_CONFIG_BASE" PREFERRED_EDITOR)
    fi

    # $EDITOR routinely carries arguments ("code --wait", "emacsclient -nw").
    # Split it into argv so the flags are passed as flags — treating the whole
    # string as one executable path would fail with "No such file" on exactly
    # the values that pass a `command -v ${editor%% *}` check.
    local -a editor_cmd=()
    [[ -n "$editor" ]] && read -r -a editor_cmd <<< "$editor"

    if [[ ${#editor_cmd[@]} -eq 0 ]] || ! command -v "${editor_cmd[0]}" >/dev/null 2>&1; then
        local candidate
        editor_cmd=()
        for candidate in nano vim vi; do
            if command -v "$candidate" >/dev/null 2>&1; then
                editor_cmd=("$candidate")
                break
            fi
        done
    fi

    if [[ ${#editor_cmd[@]} -eq 0 ]]; then
        log_warning "No editor found (tried \$EDITOR, nano, vim, vi)."
        log_warning "Edit ${DEPLOY_XO_CONFIG} from another terminal, or set \$EDITOR and re-run."
        return 0
    fi

    # The edited file is what the VM installs from, and the three prompted
    # values also drive the review screen, the post-install check and the
    # summary. Reading them back is therefore not optional bookkeeping: a value
    # that cannot be read or is out of range would install differently from
    # what the summary claims, or fail an hour into the build. Nothing has been
    # created on the pool yet, so an unusable edit can still be sent back.
    local http https branch invalid=() bad
    while true; do
        "${editor_cmd[@]}" "$DEPLOY_XO_CONFIG" < /dev/tty || {
            log_warning "The editor exited with an error; keeping the config as generated."
            return 0
        }

        invalid=()
        http=$(deploy_config_value "$DEPLOY_XO_CONFIG" HTTP_PORT)
        https=$(deploy_config_value "$DEPLOY_XO_CONFIG" HTTPS_PORT)
        branch=$(deploy_config_value "$DEPLOY_XO_CONFIG" GIT_BRANCH)

        is_port "$http"  || invalid+=("HTTP_PORT=${http:-<missing>} (must be 1-65535)")
        is_port "$https" || invalid+=("HTTPS_PORT=${https:-<missing>} (must be 1-65535)")
        [[ "$branch" =~ ^[A-Za-z0-9._/-]+$ ]] || invalid+=("GIT_BRANCH=${branch:-<missing>}")

        if [[ ${#invalid[@]} -eq 0 ]]; then
            DEPLOY_HTTP_PORT="$http"
            DEPLOY_HTTPS_PORT="$https"
            DEPLOY_GIT_BRANCH="$branch"
            break
        fi

        log_warning "The edited config has values the install would choke on:"
        for bad in "${invalid[@]}"; do
            log_warning "  ${bad}"
        done
        confirm_or_skip "Open it again to fix them?" || {
            log_error "Deploy cancelled — nothing was created on the pool."
            exit 1
        }
    done

    log_success "Config saved for the new VM"
}

# Create the VM, import the disks, and start it.
deploy_create_vm() {
    echo ""
    log_info "Creating the VM on the pool master..."

    # "Other install media" is the generic HVM template every XenServer and
    # XCP-ng release ships. It provisions no disks of its own, which is what we
    # want — we attach an imported cloud image instead.
    local template
    template=$(dom0_xe "template-list name-label='Other install media' params=uuid --minimal")
    if [[ -z "$template" ]]; then
        log_error "Could not find the 'Other install media' template on this host."
        exit 1
    fi

    DEPLOY_VM_UUID=$(dom0_xe "vm-install template=${template} new-name-label='${DEPLOY_VM_NAME}' sr-uuid=${DEPLOY_SR_UUID}")
    if [[ -z "$DEPLOY_VM_UUID" ]]; then
        log_error "VM creation failed."
        exit 1
    fi
    log_success "VM created: ${DEPLOY_VM_UUID}"

    # Some templates provision a blank disk. Remove anything that came with the
    # template so device 0 is free for the imported cloud image.
    local existing_vbds
    existing_vbds=$(dom0_xe "vbd-list vm-uuid=${DEPLOY_VM_UUID} type=Disk params=uuid --minimal" | tr ',' ' ')
    local vbd
    for vbd in $existing_vbds; do
        [[ -n "$vbd" ]] || continue
        local vdi
        vdi=$(dom0_xe "vbd-param-get uuid=${vbd} param-name=vdi-uuid" 2>/dev/null || echo "")
        dom0_xe "vbd-destroy uuid=${vbd}" >/dev/null 2>&1 || true
        if [[ -n "$vdi" && "$vdi" != "<not in database>" ]]; then
            dom0_xe "vdi-destroy uuid=${vdi}" >/dev/null 2>&1 || true
        fi
    done

    # CPU and memory. All four memory limits must be set together, and XAPI
    # requires static-max >= dynamic-max >= dynamic-min >= static-min.
    local mem="${DEPLOY_RAM_GB}GiB"
    dom0_xe "vm-param-set uuid=${DEPLOY_VM_UUID} VCPUs-max=${DEPLOY_VCPUS}" >/dev/null
    dom0_xe "vm-param-set uuid=${DEPLOY_VM_UUID} VCPUs-at-startup=${DEPLOY_VCPUS}" >/dev/null
    dom0_xe "vm-memory-limits-set uuid=${DEPLOY_VM_UUID} static-min=${mem} dynamic-min=${mem} dynamic-max=${mem} static-max=${mem}" >/dev/null

    # Settings the "Other install media" template supplies for an unknown guest,
    # corrected for the Debian appliance this actually builds. The same three
    # apply to the template builder; see tpl_create_build_vm.
    #
    # viridian is Hyper-V enlightenment and belongs to Windows guests only. The
    # base template turns it on, so without this the XO appliance runs its whole
    # life advertising itself to Linux as a Hyper-V machine.
    dom0_xe "vm-param-set uuid=${DEPLOY_VM_UUID} platform:viridian=false" >/dev/null 2>&1 || true

    # cores-per-socket defaults to 1, which presents an n-vCPU VM as n sockets.
    dom0_xe "vm-param-set uuid=${DEPLOY_VM_UUID} platform:cores-per-socket=${DEPLOY_VCPUS}" >/dev/null 2>&1 || true

    # A standard VGA adapter with 8 MiB behind it, rather than the stock 4 MiB
    # cirrus one that leaves XO's console at 640x480. See tpl_create_build_vm:
    # vga=std alone leaves videoram at the base template's 4, which produces an
    # unreadable console under UEFI, and 16 is worse.
    dom0_xe "vm-param-set uuid=${DEPLOY_VM_UUID} platform:vga=std" >/dev/null 2>&1 || true
    dom0_xe "vm-param-set uuid=${DEPLOY_VM_UUID} platform:videoram=8" >/dev/null 2>&1 || true

    # Boot straight from disk — there is no installer to boot from.
    dom0_xe "vm-param-set uuid=${DEPLOY_VM_UUID} HVM-boot-policy='BIOS order'" >/dev/null
    dom0_xe "vm-param-set uuid=${DEPLOY_VM_UUID} HVM-boot-params:order=c" >/dev/null

    # Identify this VM as ours. Without a stamp there is nothing on a deployed
    # appliance that says where it came from: XAPI writes its own generic
    # name-description for vm-install, and the platform corrections above are
    # only circumstantial — anyone setting the same values by hand produces an
    # identical record. The template builder already stamps its output (see
    # tpl_publish_template); this is the deploy path's equivalent, and the key
    # is deliberately distinct so the two are never confused.
    local deploy_stamp_version=""
    if [[ -d "${SCRIPT_DIR}/.git" ]] && command -v git &>/dev/null; then
        deploy_stamp_version=$(git -C "$SCRIPT_DIR" describe --tags --always --dirty 2>/dev/null) || deploy_stamp_version=""
    fi
    dom0_xe "vm-param-set uuid=${DEPLOY_VM_UUID} other-config:xo_deployed_by='install-xen-orchestra.sh'" >/dev/null 2>&1 || true
    dom0_xe "vm-param-set uuid=${DEPLOY_VM_UUID} other-config:xo_deploy_version='${deploy_stamp_version:-unknown}'" >/dev/null 2>&1 || true
    dom0_xe "vm-param-set uuid=${DEPLOY_VM_UUID} other-config:xo_deploy_date='$(date -u +%Y-%m-%dT%H:%M:%SZ)'" >/dev/null 2>&1 || true
    dom0_xe "vm-param-set uuid=${DEPLOY_VM_UUID} name-description='Xen Orchestra appliance deployed by install-xen-orchestra.sh'" >/dev/null 2>&1 || true

    # A tag as well, because it is the only one of these XO surfaces in its own
    # interface: tags render as chips on the VM and are filterable in the VM
    # list, whereas other-config is readable through the API and `xe` but has no
    # screen anywhere in XO that displays it. tags is a set, so it takes
    # param-add rather than param-set — param-set would replace any tags the
    # operator had already applied.
    dom0_xe "vm-param-add uuid=${DEPLOY_VM_UUID} param-name=tags param-key='xo-deployed'" >/dev/null 2>&1 || true

    # Root disk.
    log_info "Creating a ${DEPLOY_DISK_GB} GB root disk..."
    DEPLOY_ROOT_VDI=$(dom0_xe "vdi-create sr-uuid=${DEPLOY_SR_UUID} name-label='${DEPLOY_VM_NAME}-root' virtual-size=${DEPLOY_DISK_GB}GiB type=user")
    dom0_xe "vbd-create vm-uuid=${DEPLOY_VM_UUID} vdi-uuid=${DEPLOY_ROOT_VDI} device=0 bootable=true type=Disk mode=RW" >/dev/null

    # Stream the cloud image from the internet straight into the VDI, entirely
    # on the pool master — see the import helpers above for why it goes through
    # XAPI's HTTP endpoint rather than `xe vdi-import`.
    log_info "Streaming the Debian ${XO_DEPLOY_IMAGE_VERSION} cloud image into the root disk..."
    log_info "  ${XO_DEPLOY_IMAGE_URL}"
    log_info "  (this is usually the longest step)"
    if ! deploy_import_vdi_from_url "$DEPLOY_ROOT_VDI" "$XO_DEPLOY_IMAGE_URL"; then
        log_error "Failed to import the cloud image."
        log_error "Check that the pool master has outbound internet access:"
        log_error "  ssh ${HOST_USERNAME}@${POOL_MASTER_IP} curl -I ${XO_DEPLOY_IMAGE_URL}"
        log_error "Then re-run tests/probe-xapi-deploy.sh to see which import paths work."
        exit 1
    fi
    log_success "Root disk imported"

    # Config drive. 16 MiB is comfortably above the ~400 KB ISO and above the
    # allocation granularity of every SR type.
    log_info "Attaching the cloud-init config drive..."
    DEPLOY_CIDATA_VDI=$(dom0_xe "vdi-create sr-uuid=${DEPLOY_SR_UUID} name-label='${DEPLOY_VM_NAME}-cidata' virtual-size=16MiB type=user")
    if ! deploy_import_vdi_from_file "$DEPLOY_CIDATA_VDI" "$DEPLOY_CIDATA_ISO"; then
        log_error "Failed to import the cloud-init config drive."
        exit 1
    fi
    DEPLOY_CIDATA_VBD=$(dom0_xe "vbd-create vm-uuid=${DEPLOY_VM_UUID} vdi-uuid=${DEPLOY_CIDATA_VDI} device=1 type=Disk mode=RO")

    # Network interface.
    dom0_xe "vif-create vm-uuid=${DEPLOY_VM_UUID} network-uuid=${DEPLOY_NETWORK_UUID} device=0" >/dev/null

    log_info "Starting the VM..."
    dom0_xe "vm-start uuid=${DEPLOY_VM_UUID}" >/dev/null
    # From here on the guest may be reading the config drive, so an aborted run
    # warns about it rather than destroying it (see deploy_cleanup_config_drive).
    DEPLOY_VM_STARTED="true"
    log_success "VM started"
}

# Wait until the guest finishes cloud-init and accepts our key over SSH.
deploy_wait_for_guest() {
    # Trust on first use, then pin. The guest's host key is generated on its
    # first boot, so there is nothing to verify against beforehand — but
    # accepting a *different* key on every subsequent connection would let
    # anything sitting on that address swap itself in partway through, after
    # the wait loop and before xo-config.cfg is uploaded. Recording the first
    # key in a run-scoped known_hosts file closes that window; the remaining
    # exposure is an attacker already at the address when we first connect,
    # which shows up as an IP conflict the operator can see.
    local known_hosts="${DEPLOY_WORKDIR}/guest_known_hosts"
    : > "$known_hosts"
    chmod 600 "$known_hosts"

    local ssh_opts=(
        -i "$DEPLOY_SSH_KEY"
        -o IdentitiesOnly=yes
        -o StrictHostKeyChecking=accept-new
        -o UserKnownHostsFile="$known_hosts"
        -o LogLevel=ERROR
        -o ConnectTimeout=5
    )

    echo ""
    log_info "Waiting for the VM to boot and finish cloud-init..."
    log_info "(first boot installs packages and clones this repo; allow a few minutes)"

    local waited=0
    local limit=600
    while (( waited < limit )); do
        if ssh "${ssh_opts[@]}" "${DEPLOY_ADMIN_USER}@${DEPLOY_IP}" true 2>/dev/null; then
            log_success "SSH is up on ${DEPLOY_IP}"
            break
        fi
        sleep 10
        waited=$((waited + 10))
        if (( waited % 60 == 0 )); then
            log_info "  still waiting... (${waited}s)"
        fi
    done

    if (( waited >= limit )); then
        log_error "The VM did not become reachable at ${DEPLOY_IP} within ${limit}s."
        log_error "Check its console in XO Lite or XCP-ng Center and verify the network settings."
        exit 1
    fi

    # cloud-init may still be installing packages and cloning the repo.
    log_info "Waiting for cloud-init to finish..."
    if ! ssh "${ssh_opts[@]}" "${DEPLOY_ADMIN_USER}@${DEPLOY_IP}" \
        "sudo cloud-init status --wait >/dev/null 2>&1"; then
        log_warning "cloud-init reported a non-zero status; continuing anyway."
        log_warning "If the install fails, check /var/log/cloud-init-output.log in the VM."
    fi

    if ! ssh "${ssh_opts[@]}" "${DEPLOY_ADMIN_USER}@${DEPLOY_IP}" \
        "test -x ${DEPLOY_REPO_DIR}/install-xen-orchestra.sh"; then
        log_error "The repository was not cloned into the VM as expected."
        log_error "Check /var/log/cloud-init-output.log in the VM for the reason."
        exit 1
    fi

    DEPLOY_SSH_OPTS=("${ssh_opts[@]}")
    log_success "Guest is ready"
}

# How the operator reaches the VM once this run is over.
#
# Never the deployment key: by the time any of these messages are read it has
# either been revoked or gone with DEPLOY_WORKDIR on the EXIT trap. What is
# left is whatever the operator brought -- their own key, a password login if
# they enabled one, or the console.
deploy_access_hint() {
    if [[ -n "${DEPLOY_USER_PUBKEY:-}" ]]; then
        echo "  ssh ${DEPLOY_ADMIN_USER}@${DEPLOY_IP}   (using the key you supplied)"
    elif [[ "${DEPLOY_ADMIN_SSH_PWAUTH:-false}" == "true" ]]; then
        echo "  ssh ${DEPLOY_ADMIN_USER}@${DEPLOY_IP}   (password login, as you enabled)"
    else
        echo "  the VM's console in XO Lite or XCP-ng Center, as ${DEPLOY_ADMIN_USER}"
    fi
}

# Copy the generated config into the VM and run the installer over SSH.
deploy_install_xo_in_vm() {
    echo ""
    echo "=============================================="
    echo "  Installing Xen Orchestra in the VM"
    echo "=============================================="
    echo ""

    scp "${DEPLOY_SSH_OPTS[@]}" "$DEPLOY_XO_CONFIG" \
        "${DEPLOY_ADMIN_USER}@${DEPLOY_IP}:${DEPLOY_REPO_DIR}/xo-config.cfg" >/dev/null

    log_info "Running the installer in the VM — output follows."
    echo ""

    # -t gives the remote script a TTY so its progress output renders normally.
    # XO_NO_SELF_UPDATE stops the remote copy from re-execing mid-install; the
    # clone is already at the tip of whatever branch it was cloned from.
    if ! ssh -t "${DEPLOY_SSH_OPTS[@]}" "${DEPLOY_ADMIN_USER}@${DEPLOY_IP}" \
        "cd ${DEPLOY_REPO_DIR} && XO_NO_SELF_UPDATE=1 ./install-xen-orchestra.sh --install --non-interactive"; then
        log_error "The Xen Orchestra install failed inside the VM."
        log_error "The VM is still running. Reach it through:"
        # Not the deployment key: it lives in DEPLOY_WORKDIR, which the EXIT
        # trap deletes on the way out of this very failure.
        log_error "$(deploy_access_hint)"
        log_error "Then look at ${DEPLOY_REPO_DIR} and /var/log/cloud-init-output.log."
        exit 1
    fi
}

# Confirm XO actually answers before declaring success.
deploy_verify_xo() {
    echo ""
    log_info "Verifying that Xen Orchestra is responding..."

    local code
    code=$(ssh "${DEPLOY_SSH_OPTS[@]}" "${DEPLOY_ADMIN_USER}@${DEPLOY_IP}" \
        "curl -s -k -o /dev/null -w '%{http_code}' https://127.0.0.1:${DEPLOY_HTTPS_PORT}/signin" 2>/dev/null || echo "000")

    if [[ "$code" == "200" ]]; then
        log_success "Xen Orchestra is serving its sign-in page"
        return 0
    fi

    log_warning "Xen Orchestra returned HTTP ${code} instead of 200."
    log_warning "The service may still be starting. Check it from:"
    log_warning "$(deploy_access_hint)"
    log_warning "with: sudo systemctl status xo-server"
    return 0
}

# Redact the copies of the cloud-init user-data that survive the config drive.
#
# Destroying the VDI removes the drive, but cloud-init has already cached the
# user-data it read from it inside the guest -- /var/lib/cloud/instance and
# /var/lib/cloud/instances/<id>, plus the DEBUG-level cloud-init log Debian
# ships enabled. Those copies hold the admin account's password hash, so the
# drive being gone is only half the cleanup.
#
# Both paths are best-effort: a VM that is otherwise fine should not fail the
# deploy because a log could not be rewritten, but the operator is told.
deploy_scrub_guest_cloudinit_cache() {
    # The hash is fed to the guest over stdin below; xtrace would print it.
    local -
    set +x

    [[ ${#DEPLOY_SSH_OPTS[@]} -gt 0 ]] || return 0

    log_info "Redacting the cached cloud-init user-data in the VM..."

    # A valid, empty cloud-config replaces the cached user-data rather than the
    # files being deleted: cloud-init reads them on a later boot and an empty
    # document is understood, where a missing or malformed one logs errors.
    #
    # cloud-config.txt is the *rendered* config, and it carries hashed_passwd
    # just as the raw user-data does. Current cloud-init writes it 0600 under a
    # 0700 directory, so it is not an exposure on its own -- but leaving the
    # credential in a second copy while carefully scrubbing the first is not a
    # cleanup, so it goes with the rest.
    local scrub_files='
set -e
for f in /var/lib/cloud/instance/user-data.txt \
         /var/lib/cloud/instance/user-data.txt.i \
         /var/lib/cloud/instance/cloud-config.txt \
         /var/lib/cloud/instances/*/user-data.txt \
         /var/lib/cloud/instances/*/user-data.txt.i \
         /var/lib/cloud/instances/*/cloud-config.txt; do
    [ -f "$f" ] || continue
    printf "#cloud-config\n# Redacted by install-xen-orchestra --deploy.\n" > "$f"
    chmod 0600 "$f"
    chown root:root "$f"
done
'
    if ! ssh "${DEPLOY_SSH_OPTS[@]}" "${DEPLOY_ADMIN_USER}@${DEPLOY_IP}" \
        "sudo sh -c '${scrub_files}'" >/dev/null 2>&1; then
        log_warning "Could not redact the cached cloud-init user-data in the VM."
        log_warning "It holds the admin password hash. Remove it by hand with:"
        log_warning "  sudo truncate -s 0 /var/lib/cloud/instance/user-data.txt"
    fi

    # Nothing to strip from the logs when no password was set: the only other
    # thing user-data carries is the public key and the repository URL.
    [[ -n "${DEPLOY_ADMIN_PASSWORD_HASH:-}" ]] || return 0

    # The hash goes over stdin, never onto the guest's command line, where it
    # would sit in the process list for anyone running ps during the rewrite.
    # That rules out a heredoc for the program itself -- it would take the same
    # stdin -- so the program travels base64-encoded in the command instead,
    # which also spares it a round of shell quoting. cloud-init requires
    # python3, so the guest is guaranteed to have it.
    local py_prog py_b64
    py_prog='
import glob, os, sys
secret = sys.stdin.readline().strip()
if secret:
    paths = glob.glob("/var/log/cloud-init.log*")
    paths += glob.glob("/var/log/cloud-init-output.log*")
    for path in paths:
        try:
            with open(path, "r", errors="replace") as fh:
                data = fh.read()
            if secret in data:
                with open(path, "w") as fh:
                    fh.write(data.replace(secret, "<redacted>"))
                os.chmod(path, 0o600)
        except OSError:
            pass
'
    py_b64=$(printf '%s' "$py_prog" | base64 | tr -d '\n')

    if ! printf '%s\n' "$DEPLOY_ADMIN_PASSWORD_HASH" | ssh "${DEPLOY_SSH_OPTS[@]}" \
        "${DEPLOY_ADMIN_USER}@${DEPLOY_IP}" \
        "sudo python3 -c \"import base64;exec(base64.b64decode('${py_b64}'))\"" >/dev/null 2>&1; then
        log_warning "Could not scan the VM's cloud-init logs for the password hash."
        log_warning "Check /var/log/cloud-init.log in the VM if that matters to you."
    else
        log_success "Cached cloud-init user-data redacted"
    fi
}

# Revoke the passwordless sudo the unattended install needed.
#
# cloud-init grants "ALL=(ALL) NOPASSWD:ALL" because the install runs over SSH
# with no TTY to answer a password prompt. That grant has no reason to outlive
# the install, and leaving it turns the deploy key into unauthenticated root on
# the appliance -- the finding every baseline (CIS Debian 5.3.4 among them)
# raises. So it is rewritten to the ordinary "ALL=(ALL:ALL) ALL" here.
#
# It only runs when the admin account actually has a password. Requiring one
# from an account created with lock_passwd would not harden the VM, it would
# lock the operator out of root entirely, recoverable only from the console in
# single-user mode. deploy_prompt_admin_password now insists on a password, so
# this guard should never fire on a normal deploy -- it stays because the cost
# of being wrong about that is an unrecoverable VM.
#
# The rewrite is validated before and after it lands, and rolled back if the
# resulting sudoers tree does not parse: a broken /etc/sudoers.d file is the
# same lockout by a different route.
deploy_harden_guest_sudo() {
    # Reads DEPLOY_ADMIN_PASSWORD_HASH below, which xtrace would print verbatim
    # -- including in the `[[ -z ... ]]` test. See the note above dom0_exec.
    local -
    set +x

    [[ ${#DEPLOY_SSH_OPTS[@]} -gt 0 ]] || return 0

    DEPLOY_SUDO_HARDENED="false"

    if [[ -z "${DEPLOY_ADMIN_PASSWORD_HASH:-}" ]]; then
        log_warning "Leaving passwordless sudo in place for ${DEPLOY_ADMIN_USER}."
        log_warning "The account has no password, so requiring one for sudo would lock"
        log_warning "you out of root. Set a password in the VM, then tighten it with:"
        log_warning "  sudo passwd ${DEPLOY_ADMIN_USER}"
        log_warning "  echo '${DEPLOY_ADMIN_USER} ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/90-cloud-init-users"
        return 0
    fi

    log_info "Revoking the passwordless sudo used for the install..."

    # DEPLOY_ADMIN_USER is validated against ^[a-z_][a-z0-9_-]*$ when it is
    # read, so it is safe to interpolate into the remote script.
    local harden='
set -e
f=/etc/sudoers.d/90-cloud-init-users
b=$(mktemp) || exit 1
t=$(mktemp) || exit 1
if [ -f "$f" ]; then cp -a "$f" "$b"; fi
{
    echo "# Rewritten by install-xen-orchestra --deploy once the install finished."
    echo "# cloud-init granted NOPASSWD for the unattended install; that is over."
    echo "'"${DEPLOY_ADMIN_USER}"' ALL=(ALL:ALL) ALL"
} > "$t"
chmod 0440 "$t"
visudo -cf "$t" >/dev/null 2>&1 || { rm -f "$b" "$t"; exit 2; }
install -o root -g root -m 0440 "$t" "$f"
if ! visudo -c >/dev/null 2>&1; then
    # Remove before restoring: the file we just wrote is 0440, and cp onto a
    # read-only destination fails. Unlinking it only needs write permission on
    # /etc/sudoers.d, which we have. cp -a puts back the original mode and owner.
    rm -f "$f"
    if [ -s "$b" ]; then cp -a "$b" "$f" || true; fi
    rm -f "$b" "$t"
    exit 3
fi
rm -f "$b" "$t"
'
    if ssh "${DEPLOY_SSH_OPTS[@]}" "${DEPLOY_ADMIN_USER}@${DEPLOY_IP}" \
        "sudo sh -c '${harden}'" >/dev/null 2>&1; then
        DEPLOY_SUDO_HARDENED="true"
        log_success "sudo now requires ${DEPLOY_ADMIN_USER}'s password (ALL=(ALL:ALL) ALL)"
    else
        log_warning "Could not tighten sudo in the VM; the passwordless rule is still there."
        log_warning "The VM is otherwise fine. Change it by hand with:"
        log_warning "  sudo visudo -f /etc/sudoers.d/90-cloud-init-users"
        log_warning "  # replace the NOPASSWD line with:"
        log_warning "  ${DEPLOY_ADMIN_USER} ALL=(ALL:ALL) ALL"
    fi
}

# Detach and destroy the cloud-init config drive once the guest no longer
# needs it.
#
# It has done its job by this point: cloud-init has run and cached its result
# in /var/lib/cloud, and netplan's config is written to the root disk, so the
# static address survives without it. Leaving it attached would leave the
# admin account's password hash sitting on a 16 MiB disk that anyone able to
# attach a VDI could read and crack offline, and would re-seed cloud-init on
# any clone of this VM — giving the clone the same static IP as the original.
#
# Best-effort: the install has already succeeded, so a hot-unplug that the
# guest refuses is a warning with the manual commands, never a failed deploy.
deploy_remove_config_drive() {
    [[ -n "${DEPLOY_CIDATA_VDI:-}" ]] || return 0

    log_info "Removing the cloud-init config drive from the VM..."

    if [[ -n "${DEPLOY_CIDATA_VBD:-}" ]]; then
        if ! dom0_xe "vbd-unplug uuid=${DEPLOY_CIDATA_VBD}" >/dev/null 2>&1; then
            log_warning "The guest did not release the config drive; leaving it attached."
            log_warning "Remove it later (it holds your admin password hash) with:"
            log_warning "  xe vbd-unplug uuid=${DEPLOY_CIDATA_VBD}"
            log_warning "  xe vbd-destroy uuid=${DEPLOY_CIDATA_VBD}"
            log_warning "  xe vdi-destroy uuid=${DEPLOY_CIDATA_VDI}"
            # The operator has the commands; don't have the EXIT trap repeat
            # them a second time on the way out.
            DEPLOY_CIDATA_VDI=""
            DEPLOY_CIDATA_VBD=""
            return 0
        fi
        dom0_xe "vbd-destroy uuid=${DEPLOY_CIDATA_VBD}" >/dev/null 2>&1 || true
    fi

    if dom0_xe "vdi-destroy uuid=${DEPLOY_CIDATA_VDI}" >/dev/null 2>&1; then
        log_success "Config drive detached and destroyed"
    else
        log_warning "Could not destroy the config drive VDI ${DEPLOY_CIDATA_VDI}."
        log_warning "Remove it by hand with: xe vdi-destroy uuid=${DEPLOY_CIDATA_VDI}"
    fi
    DEPLOY_CIDATA_VDI=""
    DEPLOY_CIDATA_VBD=""
}

# The program deploy_revoke_deploy_key runs on the guest, kept in its own
# function so the tests can exercise it directly -- it edits authorized_keys,
# and a bug here locks the operator out of a VM they just paid to build.
#
# The key to remove arrives as the first positional argument. stdin carries
# this script itself -- it is piped into `sh -s` rather than embedded in a
# quoted `sh -c` string, because the comments below contain apostrophes and
# those closed the single-quoting early, sending the guest a truncated program
# that could not parse and left the key in place.
#
# An empty pattern aborts instead of matching every line, which is the
# difference between revoking one key and wiping the file.
deploy_revoke_script() {
    cat <<'REVOKE_EOF'
p=$1
[ -n "$p" ] || exit 1
f="$HOME/.ssh/authorized_keys"
[ -f "$f" ] || exit 0
t=$(mktemp) || exit 1
grep -vxF "$p" "$f" > "$t" 2>/dev/null
rc=$?
# grep's three outcomes are not interchangeable here:
#   0  lines were kept  -> write them back
#   1  nothing was kept  -> the deploy key was the only line; an empty file is
#      the correct result, so this is success, not failure
#  >1  grep itself failed (no space for $t, unreadable $f) -> $t is empty or
#      truncated and writing it back would erase the operator's own key. Bail
#      out and leave authorized_keys exactly as it was; the caller's
#      verification step then reports the key as still live, which is true.
if [ "$rc" -gt 1 ]; then
    rm -f "$t"
    exit 1
fi
cat "$t" > "$f"
rm -f "$t"
chmod 600 "$f"
REVOKE_EOF
}

# Take the deployment key back out of the VM.
#
# This is the last remote step of a deploy, and it is what makes the generated
# keypair a deployment credential rather than a login. Until now the key was
# needed: it is how the installer, the config upload, the cache scrub and the
# sudo rewrite all reached the guest. Once those are done it has no further
# purpose, and leaving it would mean an unencrypted, passphraseless private key
# granting root-equivalent access -- which is precisely the finding this
# replaces. The private half never leaves DEPLOY_WORKDIR and goes with it when
# the EXIT trap fires; this removes the public half from the guest so that even
# a copy that leaked in the meantime opens nothing.
#
# Only our own line is removed, matched in full and literally, so a key the
# operator asked for stays exactly where cloud-init put it.
deploy_revoke_deploy_key() {
    [[ ${#DEPLOY_SSH_OPTS[@]} -gt 0 ]] || return 0
    [[ -n "${DEPLOY_PUBKEY:-}" ]] || return 0

    log_info "Removing the temporary deployment key from the VM..."

    # The script goes to the remote `sh` on stdin, not inside a quoted -c
    # argument. Wrapping it in single quotes was silently broken: the body
    # carries apostrophes in its comments, and the first one closed the quoting
    # early, so the guest received a truncated program, failed to parse it, and
    # left the key in place. Feeding it on stdin means nothing in the script is
    # re-parsed by the local shell or the login shell on the far side.
    #
    # That frees stdin, so the key to match now arrives as a positional
    # argument instead. It is base64 plus a comment, quoted here and read back
    # with "$1" on the guest, so it is not word-split or globbed either.
    # ssh hands its command to a login shell on the guest, so the key has to
    # survive one round of shell parsing there. Each embedded ' is closed,
    # escaped and reopened ('\''), which is the only form safe inside single
    # quotes. An OpenSSH public key never contains one, but the escaping costs
    # nothing and the alternative is a quoting bug that silently skips the
    # revocation -- which is exactly the failure this function just had.
    local quoted_pubkey
    quoted_pubkey=$(printf "%s" "$DEPLOY_PUBKEY" | sed "s/'/'\\\\''/g")

    if ! ssh "${DEPLOY_SSH_OPTS[@]}" \
        "${DEPLOY_ADMIN_USER}@${DEPLOY_IP}" \
        "sh -s -- '${quoted_pubkey}'" < <(deploy_revoke_script) >/dev/null 2>&1; then
        log_warning "Could not remove the deployment key from the VM."
        log_warning "It is still in ~${DEPLOY_ADMIN_USER}/.ssh/authorized_keys, commented"
        log_warning "'install-xen-orchestra deploy (temporary)'. Delete that line by hand."
        return 0
    fi

    # Verify rather than assume: a revocation that silently did nothing is
    # worse than no revocation, because the summary would report it as done.
    # BatchMode stops ssh falling back to a password prompt and hanging here.
    if ssh -o BatchMode=yes "${DEPLOY_SSH_OPTS[@]}" \
        "${DEPLOY_ADMIN_USER}@${DEPLOY_IP}" true >/dev/null 2>&1; then
        log_warning "The deployment key still opens a session on the VM."
        log_warning "Check ~${DEPLOY_ADMIN_USER}/.ssh/authorized_keys and remove the line"
        log_warning "commented 'install-xen-orchestra deploy (temporary)'."
        return 0
    fi

    DEPLOY_KEY_REVOKED="true"
    DEPLOY_SSH_OPTS=()
    log_success "Deployment key revoked; it no longer opens the VM"
}

deploy_print_summary() {
    local url_host="$DEPLOY_IP"
    local url="https://${url_host}"
    [[ "$DEPLOY_HTTPS_PORT" != "443" ]] && url="https://${url_host}:${DEPLOY_HTTPS_PORT}"

    echo ""
    echo "=============================================="
    log_success "Xen Orchestra deployed"
    echo "=============================================="
    echo ""
    echo "  Web UI:      ${url}"
    echo "  Login:       admin@admin.net / admin  (default — change it, see below)"
    echo ""
    echo "  VM name:     ${DEPLOY_VM_NAME}"
    echo "  VM UUID:     ${DEPLOY_VM_UUID}"
    echo "  Address:     ${DEPLOY_IP}/${DEPLOY_PREFIX}"
    echo ""
    if [[ -n "${DEPLOY_USER_PUBKEY:-}" ]]; then
        echo "  SSH:         ssh ${DEPLOY_ADMIN_USER}@${DEPLOY_IP}"
        echo "               (your key: $(deploy_pubkey_label "$DEPLOY_USER_PUBKEY"))"
    elif [[ "$DEPLOY_ADMIN_SSH_PWAUTH" == "true" ]]; then
        echo "  SSH:         ssh ${DEPLOY_ADMIN_USER}@${DEPLOY_IP}  (password login)"
    else
        echo "  SSH:         none — no key was installed and password logins are off"
    fi
    if [[ "$DEPLOY_ADMIN_SSH_PWAUTH" == "true" ]]; then
        echo "  Console/SSH: user ${DEPLOY_ADMIN_USER} with the password you chose"
    else
        echo "  Console:     user ${DEPLOY_ADMIN_USER} with the password you chose"
    fi
    if [[ "$DEPLOY_KEY_REVOKED" == "true" ]]; then
        echo "  Deploy key:  revoked — the temporary install key no longer opens the VM"
    else
        echo "  Deploy key:  NOT revoked — see the warning below"
    fi
    if [[ "$DEPLOY_SUDO_HARDENED" == "true" ]]; then
        echo "  sudo:        asks for ${DEPLOY_ADMIN_USER}'s password (ALL=(ALL:ALL) ALL)"
    else
        echo "  sudo:        passwordless for ${DEPLOY_ADMIN_USER} — see the warning below"
    fi
    echo ""
    echo "  This repo lives at ${DEPLOY_REPO_DIR} inside the VM."
    echo "  To update Xen Orchestra later, run there:"
    echo ""
    echo "    cd ${DEPLOY_REPO_DIR} && ./install-xen-orchestra.sh --update"
    echo ""
    echo "=============================================="
    echo "  Before you put this VM to use"
    echo "=============================================="
    echo ""
    log_warning "1. HIGHLY RECOMMENDED: change the Xen Orchestra web login."
    echo "     admin@admin.net / admin are Xen Orchestra's published defaults, so"
    echo "     anyone who can reach ${url} is an administrator until you"
    echo "     change them — and this appliance holds your pool's root credentials."
    echo "     Sign in, open Settings -> Users (or the account menu -> Profile),"
    echo "     set a strong unique password, and enable OTP while you are there."
    echo ""
    local n=2
    if [[ "$DEPLOY_KEY_REVOKED" != "true" ]]; then
        # Boxed, unlike its neighbours. Every other item here is something to
        # tighten at leisure; this one is a live passphraseless credential that
        # opens a root-capable session on an appliance holding the pool's root
        # password, and it is the only item the operator must act on before the
        # VM is safe to leave. It was being missed in the run of warnings.
        echo -e "${RED}  ┌────────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${RED}  │  ${YELLOW}!!  ACTION REQUIRED — DEPLOYMENT KEY STILL LIVE  !!${RED}                │${NC}"
        echo -e "${RED}  └────────────────────────────────────────────────────────────────────┘${NC}"
        log_warning "${n}. The temporary deployment key was NOT removed from the VM."
        echo "     It is an unencrypted key with no passphrase and it still opens a"
        echo "     root-capable session. Delete its line from"
        echo "     ~${DEPLOY_ADMIN_USER}/.ssh/authorized_keys — the one commented"
        echo "     'install-xen-orchestra deploy (temporary)':"
        echo ""
        echo -e "       ${YELLOW}sed -i '/install-xen-orchestra deploy (temporary)/d' ~/.ssh/authorized_keys${NC}"
        echo ""
        echo -e "${RED}  ────────────────────────────────────────────────────────────────────${NC}"
        echo ""
        n=$((n + 1))
    fi
    if [[ -z "${DEPLOY_USER_PUBKEY:-}" && "$DEPLOY_ADMIN_SSH_PWAUTH" != "true" ]]; then
        log_warning "${n}. This VM has no SSH access at all."
        echo "     No key was installed and password logins are off, which is the most"
        echo "     locked-down outcome but also means the console is the only way in."
        echo "     To add your key later, from the console:"
        echo "       mkdir -p ~/.ssh && chmod 700 ~/.ssh"
        echo "       echo '<your public key>' >> ~/.ssh/authorized_keys"
        echo "       chmod 600 ~/.ssh/authorized_keys"
        echo ""
        n=$((n + 1))
    fi
    if [[ "$DEPLOY_SUDO_HARDENED" != "true" ]]; then
        log_warning "${n}. ${DEPLOY_ADMIN_USER} still has passwordless sudo."
        echo "     The rewrite could not be applied, so the rule cloud-init used for the"
        echo "     unattended install is still in place. Tighten it with:"
        echo "       sudo visudo -f /etc/sudoers.d/90-cloud-init-users"
        echo "       # replace the NOPASSWD line with:"
        echo "       ${DEPLOY_ADMIN_USER} ALL=(ALL:ALL) ALL"
        echo ""
        n=$((n + 1))
    fi
    echo "  The web UI uses a self-signed certificate, so the browser warning on"
    echo "  first visit is expected. Replace it with your own certificate in"
    echo "  /etc/ssl/xo inside the VM if you have one."
    echo ""
}

# Turn this checkout's origin into a URL the new VM can actually clone from.
#
# Two things make a local origin unusable in the guest:
#
#   - an SSH remote (git@host:owner/repo.git, ssh://git@host/owner/repo.git)
#     authenticates with the operator's key, which the VM does not have and is
#     not given — the clone would fail on first boot with a permission error
#     buried in the cloud-init log;
#   - an HTTPS remote carrying userinfo (https://user:token@host/...) would
#     copy that credential into the guest's user-data, where it is readable by
#     anyone on the VM and echoed into cloud-init's logs.
#
# Both are rewritten to a plain, credential-free HTTPS URL. Echoes the result;
# the caller compares it against the original to decide what to report.
deploy_guest_clone_url() {
    local url="$1" rest host path scheme

    if [[ "$url" != *"://"* && "$url" == *@*:* ]]; then
        # scp-style SSH remote: user@host:path
        host="${url#*@}"; host="${host%%:*}"
        path="${url#*:}"
        url="https://${host}/${path}"
    elif [[ "$url" == ssh://* || "$url" == git+ssh://* || "$url" == git://* ]]; then
        rest="${url#*://}"
        rest="${rest#*@}"
        host="${rest%%/*}"
        path="${rest#*/}"
        host="${host%%:*}"          # drop any port; the HTTPS one differs anyway
        url="https://${host}/${path}"
    fi

    # Strip userinfo from an http(s) URL, whether it was there all along or
    # arrived via one of the rewrites above.
    if [[ "$url" == http://* || "$url" == https://* ]]; then
        scheme="${url%%://*}"
        rest="${url#*://}"
        if [[ "${rest%%/*}" == *@* ]]; then
            rest="${rest#*@}"
        fi
        url="${scheme}://${rest}"
    fi

    printf '%s' "$url"
}

# Orchestrator for --deploy.
deploy_xo_vm() {
    echo ""
    echo "=============================================="
    echo "  Deploy Xen Orchestra to a new VM"
    echo "=============================================="
    echo ""
    echo "This creates a Debian ${XO_DEPLOY_IMAGE_VERSION} VM on a XenServer/XCP-ng pool and"
    echo "installs Xen Orchestra from source into it. Nothing is installed on"
    echo "this machine."
    echo ""
    echo "You will need:"
    echo "  - the pool master's IP and root password"
    echo "  - a free static IP on the network the VM will use"
    echo "  - a pool master with outbound internet access"
    echo ""

    if [[ "$DRY_RUN" == "true" ]]; then
        log_warning "[DRY-RUN] --deploy creates a VM on a remote host and cannot be"
        log_warning "[DRY-RUN] meaningfully simulated. No changes were made."
        return 0
    fi

    # The image URL is interpolated into a single-quoted argument in a shell on
    # the pool master, so it is checked before anything else happens — an
    # override that cannot be sent safely is a mistake to report now, not after
    # the operator has answered a dozen prompts.
    if ! is_safe_url "$XO_DEPLOY_IMAGE_URL"; then
        log_error "XO_DEPLOY_IMAGE_URL is not a usable http(s) URL:"
        log_error "  ${XO_DEPLOY_IMAGE_URL}"
        exit 1
    fi

    confirm_or_skip "Continue?" || { log_info "Deploy cancelled."; return 0; }

    DEPLOY_WORKDIR=$(mktemp -d --tmpdir xo-deploy-XXXXXX)
    chmod 700 "$DEPLOY_WORKDIR"
    trap deploy_cleanup EXIT

    # Deploy whatever fork this checkout came from, so the VM ends up tracking
    # the same repository the user is running.
    local origin_url upstream_url="https://github.com/acebmxer/install_xen_orchestra.git"
    origin_url=$(git -C "$SCRIPT_DIR" remote get-url origin 2>/dev/null || echo "$upstream_url")
    DEPLOY_REPO_URL=$(deploy_guest_clone_url "$origin_url")

    if [[ "$DEPLOY_REPO_URL" != http://* && "$DEPLOY_REPO_URL" != https://* ]]; then
        log_warning "This checkout's origin is not a URL the VM could clone from."
        log_warning "Falling back to ${upstream_url}"
        DEPLOY_REPO_URL="$upstream_url"
    elif [[ "$DEPLOY_REPO_URL" != "$origin_url" ]]; then
        # Deliberately prints only the rewritten URL — the original may hold a
        # token, and this line goes to the terminal and to any log capturing it.
        log_info "Origin rewritten for the guest (no key or credentials of yours"
        log_info "are copied into the VM): ${DEPLOY_REPO_URL}"
    fi

    deploy_check_local_deps
    deploy_connect_pool_master
    deploy_pick_sr
    deploy_pick_network
    deploy_prompt_vm_specs
    deploy_prompt_network_settings
    deploy_prompt_xo_settings

    # Built before the review, not after it, so the config can be inspected and
    # edited while nothing has been created on the pool yet.
    deploy_build_xo_config
    deploy_edit_xo_config

    echo ""
    echo "=============================================="
    echo "  Review"
    echo "=============================================="
    echo ""
    echo "  Pool master:  ${HOST_USERNAME}@${POOL_MASTER_IP}"
    echo "  VM name:      ${DEPLOY_VM_NAME}"
    echo "  Resources:    ${DEPLOY_VCPUS} vCPU / ${DEPLOY_RAM_GB} GB RAM / ${DEPLOY_DISK_GB} GB disk"
    echo "  Address:      ${DEPLOY_IP}/${DEPLOY_PREFIX} via ${DEPLOY_GATEWAY} (DNS ${DEPLOY_DNS})"
    local admin_auth="console password"
    if [[ "$DEPLOY_ADMIN_SSH_PWAUTH" == "true" ]]; then
        admin_auth="password (console and SSH)"
    fi
    echo "  Admin user:   ${DEPLOY_ADMIN_USER}  (${admin_auth})"
    if [[ -n "${DEPLOY_USER_PUBKEY:-}" ]]; then
        echo "  SSH key:      $(deploy_pubkey_label "$DEPLOY_USER_PUBKEY")"
    else
        echo "  SSH key:      none (the install key is destroyed when the deploy ends)"
    fi
    echo "  Repository:   ${DEPLOY_REPO_URL}"
    echo "  Clone into:   ${DEPLOY_REPO_DIR}"
    echo "  XO config:    from ${DEPLOY_CONFIG_BASE_LABEL}"
    echo ""
    confirm_or_skip "Create this VM?" || { log_info "Deploy cancelled."; return 0; }

    deploy_build_config_drive
    deploy_create_vm
    deploy_wait_for_guest
    deploy_install_xo_in_vm
    deploy_verify_xo
    deploy_remove_config_drive
    deploy_scrub_guest_cloudinit_cache
    # Last of the steps that need passwordless sudo in the guest.
    deploy_harden_guest_sudo
    # Last step that needs the deployment key, and the one that destroys it.
    # Nothing below reaches the VM.
    deploy_revoke_deploy_key

    # Everything that could fail has now succeeded, so the EXIT trap must stop
    # treating this VM as wreckage to clear up.
    DEPLOY_SUCCEEDED="true"
    deploy_print_summary
}

# Uninstall Xen Orchestra: stop/disable the service, remove the install
# directory, systemd unit, sudoers file, SSL certs, and optionally the
# service user and Redis data.
cleanup_xo() {
    log_info "Starting Xen Orchestra uninstall..."

    check_required_commands
    check_not_root
    check_sudo
    check_systemctl
    load_config

    echo ""
    echo "=============================================="
    echo "  Xen Orchestra Uninstall"
    echo "=============================================="
    echo ""
    echo "The following will be removed:"
    echo "  - systemd service:  xo-server"
    echo "  - install dir:      ${INSTALL_DIR}"
    echo "  - data dir:         /var/lib/xo-server"
    echo "  - SSL cert dir:     ${SSL_CERT_DIR}"
    if [[ -n "${SERVICE_USER:-}" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        echo "  - sudoers file:     /etc/sudoers.d/xo-server-${SERVICE_USER}"
    fi
    echo ""

    # Removing the data dir destroys this host's half of the credential
    # encryption key. Redis itself is left alone by the uninstall, so the
    # encrypted records survive as unreadable ciphertext unless the operator
    # exported the config first. Say so before asking to proceed.
    if [[ -f /var/lib/xo-server/data/xo-encryption-key ]]; then
        log_warning "Credential encryption is in use on this host."
        log_warning "  Removing the data dir deletes this host's half of the encryption"
        log_warning "  key. Any encrypted records left in Redis become permanently"
        log_warning "  undecryptable. If you still need that data, cancel now and export"
        log_warning "  the XO config (Settings -> Config, passphrase-protected) first."
        echo ""
    fi

    if ! confirm_or_skip "Proceed with uninstall? This cannot be undone."; then
        log_info "Uninstall cancelled."
        return 0
    fi

    # 1. Stop and disable the systemd service
    if systemctl list-unit-files xo-server.service &>/dev/null 2>&1 | grep -q xo-server; then
        log_info "Stopping xo-server service..."
        run_cmd sudo systemctl stop xo-server 2>/dev/null || true
        run_cmd sudo systemctl disable xo-server 2>/dev/null || true
    fi

    # 2. Remove the systemd unit file
    if [[ -f /etc/systemd/system/xo-server.service ]]; then
        log_info "Removing systemd unit file..."
        run_cmd sudo rm -f /etc/systemd/system/xo-server.service
        run_cmd sudo systemctl daemon-reload
    fi

    # 3. Remove the sudoers file
    if [[ -n "${SERVICE_USER:-}" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        local SUDOERS_FILE="/etc/sudoers.d/xo-server-${SERVICE_USER}"
        if [[ -f "$SUDOERS_FILE" ]]; then
            log_info "Removing sudoers file..."
            run_cmd sudo rm -f "$SUDOERS_FILE"
        fi
    fi

    # 3b. Remove the XenStore-access udev rule (added for non-root encryption)
    if [[ -f /etc/udev/rules.d/40-xen-xenbus-xo.rules ]]; then
        log_info "Removing XenStore access udev rule..."
        run_cmd sudo rm -f /etc/udev/rules.d/40-xen-xenbus-xo.rules
        run_cmd sudo udevadm control --reload
    fi

    # 4. Remove the install directory
    if [[ -d "$INSTALL_DIR" ]]; then
        log_info "Removing install directory: ${INSTALL_DIR}..."
        run_cmd sudo rm -rf "$INSTALL_DIR"
    fi

    # 5. Remove the data directory
    if [[ -d /var/lib/xo-server ]]; then
        log_info "Removing data directory: /var/lib/xo-server..."
        run_cmd sudo rm -rf /var/lib/xo-server
    fi

    # 6. Remove SSL certificates
    if [[ -d "$SSL_CERT_DIR" ]]; then
        log_info "Removing SSL cert directory: ${SSL_CERT_DIR}..."
        run_cmd sudo rm -rf "$SSL_CERT_DIR"
    fi

    # 7. Optionally remove the service user
    if [[ -n "${SERVICE_USER:-}" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        if id "$SERVICE_USER" &>/dev/null; then
            echo ""
            if confirm_or_skip "Also delete system user '${SERVICE_USER}'?"; then
                log_info "Removing service user: ${SERVICE_USER}..."
                run_cmd sudo userdel -r "$SERVICE_USER" 2>/dev/null || \
                    run_cmd sudo userdel "$SERVICE_USER" 2>/dev/null || true
            fi
        fi
    fi

    # 8. Optionally remove Redis data
    echo ""
    if confirm_or_skip "Also purge Redis data? (WARNING: removes all Redis databases on this host)"; then
        log_info "Purging Redis data..."
        run_cmd sudo systemctl stop redis-server 2>/dev/null || \
            run_cmd sudo systemctl stop redis 2>/dev/null || true
        run_cmd sudo rm -rf /var/lib/redis /var/lib/valkey 2>/dev/null || true
    fi

    log_success "Xen Orchestra has been uninstalled."
    echo ""
    echo "Note: backups in ${BACKUP_DIR} were NOT removed."
    echo "      Remove them manually if no longer needed."
    echo ""
}

# Adjust the memory allocated to the xo-server Node.js process.
# When xo-server runs out of heap it logs "JavaScript heap out of memory"
# and aborts. Raising the VM RAM alone is not enough — the systemd service
# must pass --max-old-space-size to node so V8 can use the extra memory.
adjust_xo_memory() {
    local service_file="/etc/systemd/system/xo-server.service"

    log_info "Starting Xen Orchestra memory allocation adjustment..."
    echo ""

    if [[ ! -f "$service_file" ]]; then
        log_error "$service_file not found. Is Xen Orchestra installed?"
        return 1
    fi

    # Determine total system RAM in MB
    local total_ram_mb=0
    if [[ -r /proc/meminfo ]]; then
        local total_kb
        total_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null) || total_kb=0
        [[ -n "$total_kb" ]] && total_ram_mb=$((total_kb / 1024))
    fi

    # Detect the current --max-old-space-size value from the service file (if any)
    local current_exec current_limit=""
    current_exec=$(grep -E '^ExecStart=' "$service_file" 2>/dev/null | head -n1) || current_exec=""
    if [[ "$current_exec" =~ --max-old-space-size=([0-9]+) ]]; then
        current_limit="${BASH_REMATCH[1]}"
    fi

    # Resolve the node binary path (needed below to query node's default heap)
    local node_path
    node_path=$(command -v node 2>/dev/null) || node_path=""
    if [[ -z "$node_path" ]]; then
        node_path="/usr/local/bin/node"
        log_warning "node not found on PATH; assuming ${node_path}"
    fi

    # When no --max-old-space-size flag is set, node picks a default heap limit
    # based on physical RAM (~50% on modern node). Query it so the user sees the
    # real value the service is running with today, not just "default".
    local node_default_mb=""
    if [[ -x "$node_path" ]]; then
        node_default_mb=$("$node_path" -e \
            'process.stdout.write(String(Math.round(require("v8").getHeapStatistics().heap_size_limit/1048576)))' \
            2>/dev/null) || node_default_mb=""
        [[ "$node_default_mb" =~ ^[0-9]+$ ]] || node_default_mb=""
    fi

    # Suggest a heap size: total RAM minus ~512MB reserved for the Debian OS.
    # Clamp to a sane floor so we never suggest a value smaller than the default.
    local suggested=2048
    if [[ "$total_ram_mb" -gt 0 ]]; then
        suggested=$((total_ram_mb - 512))
        [[ "$suggested" -lt 1024 ]] && suggested=1024
    fi

    echo "=============================================="
    echo "  Xen Orchestra Memory Allocation"
    echo "=============================================="
    echo ""
    # Build a human-readable label for the current heap limit
    local current_label
    if [[ -n "$current_limit" ]]; then
        current_label="${current_limit} MB"
    elif [[ -n "$node_default_mb" ]]; then
        current_label="~${node_default_mb} MB (node default, no --max-old-space-size set)"
    else
        current_label="node default (no --max-old-space-size set)"
    fi

    echo "  Setting                       Value"
    echo "  ----------------------------- -----------------------------------"
    if [[ "$total_ram_mb" -gt 0 ]]; then
        printf '  %-29s %s\n' "Total system RAM" "${total_ram_mb} MB"
    else
        printf '  %-29s %s\n' "Total system RAM" "could not be detected"
    fi
    printf '  %-29s %s\n' "Current xo-server heap limit" "$current_label"
    printf '  %-29s %s\n' "Recommended heap limit" "${suggested} MB"
    echo ""
    if [[ "$total_ram_mb" -le 0 ]]; then
        log_warning "Could not detect total system RAM."
    fi
    echo "If xo-server runs out of memory you will see this in the logs"
    echo "(journalctl -u xo-server.service):"
    echo ""
    echo "    FATAL ERROR: CALL_AND_RETRY_LAST Allocation failed -"
    echo "    JavaScript heap out of memory"
    echo ""
    echo "Raising the VM's RAM alone does not fix it — the xo-server service"
    echo "must also tell node how much heap it may use."
    echo ""
    echo "The recommended heap leaves ~512 MB for the Debian OS itself."
    echo ""

    # If the service is already configured at the recommended heap size, no
    # change is needed. Show the info above, then let the user opt in anyway.
    if [[ -n "$current_limit" ]] && [[ "$current_limit" -eq "$suggested" ]]; then
        log_info "xo-server is already configured for the recommended ${suggested} MB heap."
        log_info "No changes are needed."
        echo ""
        if ! prompt_yes_no "Do you still want to make changes?"; then
            echo ""
            if prompt_yes_no "Reload the script?"; then
                log_info "Reloading ${SCRIPT_PATH}..."
                exec bash "$SCRIPT_PATH" "${ORIGINAL_ARGS[@]}"
            fi
            log_info "No changes made. Exiting memory allocation adjustment."
            return 0
        fi
        echo ""
    fi

    # Prompt for the desired heap size
    local heap_mb=""
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        heap_mb="$suggested"
        log_info "Non-interactive: using suggested heap size ${heap_mb} MB"
    else
        local input
        read -rp "Heap size in MB [${suggested}]: " input < /dev/tty
        heap_mb="${input:-$suggested}"
    fi

    # Validate: must be a positive integer
    if ! [[ "$heap_mb" =~ ^[0-9]+$ ]] || [[ "$heap_mb" -le 0 ]]; then
        log_error "Invalid heap size: '${heap_mb}'. Must be a positive integer (MB)."
        return 1
    fi

    # Sanity warnings (non-fatal)
    if [[ "$heap_mb" -lt 1024 ]]; then
        log_warning "A heap below 1024 MB may be too small for Xen Orchestra."
    fi
    if [[ "$total_ram_mb" -gt 0 ]] && [[ "$heap_mb" -ge "$total_ram_mb" ]]; then
        log_warning "Heap size (${heap_mb} MB) meets or exceeds total RAM (${total_ram_mb} MB)."
        log_warning "Leave headroom for the OS or the VM may start swapping or be OOM-killed."
    fi

    if [[ -n "$current_limit" ]] && [[ "$current_limit" -eq "$heap_mb" ]]; then
        log_info "xo-server is already configured for a ${heap_mb} MB heap. Nothing to do."
        return 0
    fi

    echo ""
    log_info "ExecStart will be updated to:"
    echo "    ExecStart=${node_path} --max-old-space-size=${heap_mb} <xo-server>"
    echo ""
    if ! confirm_or_skip "Apply this change to ${service_file}?"; then
        log_info "Skipping memory allocation adjustment."
        return 0
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Would back up and rewrite ExecStart in ${service_file}"
        echo "[DRY-RUN] Would run: systemctl daemon-reload && systemctl restart xo-server"
        return 0
    fi

    # Back up the service file before editing
    run_cmd sudo cp "$service_file" "${service_file}.backup-$(date +%Y%m%d-%H%M%S)"

    # Rewrite the ExecStart line. Two cases:
    #   1. Already has --max-old-space-size=N -> replace N
    #   2. No flag yet -> insert "node --max-old-space-size=N" before the script path
    if [[ -n "$current_limit" ]]; then
        run_cmd sudo sed -i -E \
            "s|(--max-old-space-size=)[0-9]+|\1${heap_mb}|" "$service_file"
    else
        # ExecStart=<node> <xo-server-path>  ->  ExecStart=<node> --max-old-space-size=N <xo-server-path>
        run_cmd sudo sed -i -E \
            "s|^(ExecStart=)([^[:space:]]+)([[:space:]]+)|\1\2 --max-old-space-size=${heap_mb}\3|" \
            "$service_file"
    fi

    # Verify the edit landed
    if ! grep -qE "^ExecStart=.*--max-old-space-size=${heap_mb}" "$service_file"; then
        log_error "Failed to update ExecStart in ${service_file}. Service file left unchanged."
        log_error "A backup was saved alongside the original — inspect it manually."
        return 1
    fi
    log_success "ExecStart updated to use a ${heap_mb} MB heap."

    # Refresh systemd and restart the service
    log_info "Reloading systemd and restarting xo-server..."
    run_cmd sudo systemctl daemon-reload
    run_cmd sudo systemctl restart xo-server

    log_success "xo-server restarted with a ${heap_mb} MB heap limit."
    echo ""
    log_info "Reminder: also ensure the VM itself has enough RAM"
    echo "         (heap ${heap_mb} MB + ~512 MB for the OS)."
    echo ""
}

# Show help
# Print the installed script's git revision so users can identify exactly which
# version they are running (useful in bug reports). Falls back gracefully when
# the script is run outside a git checkout.
show_version() {
    echo "Xen Orchestra Installation Script"
    if [[ -d "${SCRIPT_DIR}/.git" ]] && command -v git &>/dev/null; then
        # describe yields the nearest tag (e.g. v0.1.3), or v0.1.3-N-gHASH when
        # ahead of it, or the short hash if no tags are reachable.
        local version branch
        version=$(git -C "$SCRIPT_DIR" describe --tags --always --dirty 2>/dev/null) || version=""
        branch=$(git -C "$SCRIPT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null) || branch=""
        echo "  Version: ${version:-unknown}"
        if [[ -n "$branch" ]]; then
            echo "  Branch:  ${branch}"
        fi
    else
        echo "  Version: unknown (not a git checkout)"
    fi
    echo "  Based on: https://docs.xen-orchestra.com/install-from-sources"
}

show_help() {
    echo "Xen Orchestra Installation Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Running without options launches an interactive menu."
    echo ""
    echo "Options:"
    echo "  --install              Install Xen Orchestra directly (skip menu)"
    echo "  --update               Update existing installation"
    echo "  --restore              Restore a previous backup interactively"
    echo "  --rebuild              Fresh clone + clean build on the current branch (backup taken first)"
    echo "  --reconfigure          Regenerate config, systemd service, sudoers, and file ownership"
    echo "  --proxy                Install XO Proxy on a Xen pool master"
    echo "  --deploy               Create a Debian VM on a XenServer/XCP-ng pool and install XO into it"
    echo "  --build-templates      Build cloud-init VM templates on a XenServer/XCP-ng pool"
    echo "  --adjust-memory        Adjust the heap memory allocated to the xo-server process"
    echo "  --flush-tokens         Clear stale Redis auth tokens (e.g. after restoring an XO config)"
    echo "  --uninstall            Remove XO service, install dir, certs, and sudoers (guided)"
    echo "  --version              Show this script's version and branch, then exit"
    echo "  --help                 Show this help message"
    echo ""
    echo "Automation Flags (can be combined with any operation):"
    echo "  --non-interactive      Bypass all interactive prompts; use config defaults"
    echo "  --yes                  Alias for --non-interactive"
    echo "  --backup-file NAME     With --restore: select specific backup by directory name"
    echo "  --dry-run, --check     Show what would be done without making any changes"
    echo "  --log-file PATH        Append log output to PATH (plain-text by default)"
    echo "  --json-logs            Write structured JSON lines to --log-file instead of plain text"
    echo "  --allow-eol-distro     Continue on an end-of-life distribution (Debian 11), unsupported"
    echo ""
    echo "Environment Variables:"
    echo "  XO_DEBUG=1              Enable debug mode (prints all commands with 'set -x')"
    echo "  XO_NO_SELF_UPDATE=1     Skip automatic script self-update check"
    echo ""
    echo "Deploy Environment Variables (--deploy only):"
    echo "  XO_DEPLOY_IMAGE_VERSION  Debian major version for the guest (default: 13)"
    echo "  XO_DEPLOY_IMAGE_RELEASE  Debian codename for the guest (default: trixie)"
    echo "  XO_DEPLOY_IMAGE_URL      Full URL of a raw cloud image, overriding the two above"
    echo ""
    echo "Configuration:"
    echo "  Copy sample-xo-config.cfg to xo-config.cfg and edit as needed."
    echo "  If xo-config.cfg is not found, it will be created automatically."
    echo "  To switch branches, edit GIT_BRANCH in xo-config.cfg and run --update."
    echo ""
}

# ============================================================================
# Cloud-init VM Templates
#
# Builds XCP-ng VM templates from the distributions' own published cloud
# images, so a pool running XO from sources gets the same "pick a template,
# fill in the form, deploy" workflow that XOA's Hub provides.
#
# The Hub itself cannot be unlocked here: its catalogue is served by Vates and
# the `cloud.*` API backing it is not part of the open-source tree, so the Hub
# page is inert on a sources install no matter what the client is told. This
# builds the equivalent from upstream instead -- the images come from Debian,
# Ubuntu and friends directly, which means no third-party redistribution and a
# version the operator can pin.
#
# A template is not a file that can be copied in. It is a VM object whose disk
# has been prepared and which is then flagged as a template, so building one
# means importing the image, booting it once to install the guest tools, and
# scrubbing the machine-specific state the clone must not inherit. The boot is
# the slow part and the reason this is not instant: XCP-ng's guest agent has to
# be installed *inside* the image for XO to report a VM's IP address, and no
# amount of API work does that from outside.
# ============================================================================

# Catalogue of buildable templates. Each entry is:
#   key|display name|codename|image URL|default user|prep function
#
# The URL points at the distribution's own mirror. Checksums are not pinned
# here: every origin in this list publishes a SHA512SUMS beside the image, and
# tpl_verify_checksum reads it at build time, so a new upstream release is
# picked up without this table having to be edited.
#
# ---------------------------------------------------------------------------
# Pick the variant with a full kernel, not the "cloud" one
# ---------------------------------------------------------------------------
#
# Debian publishes genericcloud and generic side by side, identical in size and
# nearly identical in name. They do not ship the same kernel -- read out of the
# images themselves:
#
#   genericcloud  vmlinuz-6.12.107+deb13-cloud-amd64
#   generic       vmlinuz-6.12.107+deb13-amd64
#
# The cloud kernel is trimmed for headless virtual machines and leaves out the
# framebuffer and DRM drivers a graphical console needs. A VM built from it runs
# perfectly -- boots, gets an IP, runs the guest agent -- and its console in XO
# is unreadable garbage from the first frame, worst under UEFI. Nothing reports
# an error, because nothing has failed.
#
# So this table uses generic. The equivalent trap exists for other
# distributions under other names; when adding an image, check what kernel it
# carries rather than taking the most cloud-sounding filename.
#
# ---------------------------------------------------------------------------
# Adding an image: boot firmware is decided from the disk, not from this table
# ---------------------------------------------------------------------------
#
# Nothing about firmware is declared here, and nothing should be. After the
# build boot, tpl_disk_supports_uefi reads the imported disk's GPT and looks for
# an EFI system partition; tpl_seal_template then publishes the template as UEFI
# when one is present and as BIOS when it is not. XO's New VM form offers that
# as its "Boot firmware" default, so it is what an operator gets without opening
# advanced settings.
#
# UEFI is preferred wherever the image supports it -- it is required for Secure
# Boot and a vTPM, and the cloud images that ship an ESP ship a BIOS boot
# partition beside it, so choosing BIOS in the dropdown still produces a working
# VM. The reverse is not true: UEFI firmware with no bootloader to load does not
# fall back to BIOS, it fails to boot.
#
# So a new entry needs no firmware decision made for it, and none should be
# hardcoded. Two things worth knowing when adding one:
#
#   - Judge from the disk, never from the distribution. Whether an image is
#     UEFI-bootable is a property of that image, and vendors ship BIOS-only and
#     UEFI-capable variants under similar names.
#   - Early boot output can render as coloured noise under UEFI and then correct
#     itself once the kernel takes over the framebuffer. That is normal and is
#     not evidence of a failed boot -- XO's own Hub templates do the same thing.
#     Do not read a garbled console as a missing ESP.
TPL_CATALOG=(
    "debian13|Debian 13 (Trixie)|trixie|https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.raw|debian|tpl_prep_debian"
)

# Where the guest tools ISO lives. Every XCP-ng host ships this SR; the ISO
# inside it is what installs the guest agent, and its absence is the one
# failure that leaves a template XO cannot report an IP for.
TPL_TOOLS_ISO_NAME="guest-tools.iso"

# Default sizing for the template itself. These are what the New VM form is
# pre-filled with; the operator overrides them per VM at creation time, so they
# are starting points rather than limits.
TPL_DEFAULT_RAM_GB=2
TPL_DEFAULT_VCPUS=2

# The template's own disk. cloud-init's growpart expands the filesystem to fill
# whatever the operator asks for at deploy time, so this only has to hold the
# image.
#
# It was 8 GiB, on the belief that a VDI sized close to the image left the raw
# import "no margin" and made it fail. That was wrong, and it came from the same
# mistaken reading that treated a correctly imported sparse disk as an empty
# one. XO's own Hub template for this image is 3,223,322,624 bytes against a
# 3,221,225,472-byte image -- about two megabytes of headroom -- and imports
# fine.
#
# 4 GiB keeps a real margin over the current 3 GiB images without inflating
# every VM cloned from the template, since a clone starts at the template's size
# unless the operator asks for more. Sized in GiB rather than to the image so a
# slightly larger upstream release does not silently start failing; if an image
# ever approaches this, the number moves.
TPL_DEFAULT_DISK_GB=4

# State for the build in progress, cleared between templates.
TPL_VM_UUID=""
TPL_ROOT_VDI=""
TPL_CIDATA_VDI=""
TPL_CIDATA_ISO=""
TPL_SSH_KEY=""
TPL_BUILD_STARTED="false"
# The guest agent's version, observed while the build VM was still running.
# XAPI clears PV-drivers-version when the domain goes away, so it cannot be
# read after the preparation boot powers the VM off.
TPL_AGENT_SEEN=""

# --- Catalogue helpers ------------------------------------------------------

# Field n of a catalogue row, 1-indexed.
tpl_field() {
    local row="$1" n="$2"
    cut -d'|' -f"$n" <<< "$row"
}

# Find a catalogue row by its key. Prints the row, or nothing when unknown.
tpl_row_for_key() {
    local want="$1" row
    for row in "${TPL_CATALOG[@]}"; do
        [[ "$(tpl_field "$row" 1)" == "$want" ]] && { printf '%s\n' "$row"; return 0; }
    done
    return 1
}

# --- Template existence -----------------------------------------------------

# The name a built template carries. Kept in one function because both the
# build and the "already present" check have to agree on it exactly, and a
# mismatch would rebuild a template that already exists on every run.
tpl_template_name() {
    local display="$1"
    printf '%s Cloud-init' "$display"
}

# True when a template of this name is already on the pool. Checked before
# building rather than after, so a re-run costs one `xe` call instead of a
# download and a boot.
tpl_template_exists() {
    local name="$1" found
    found=$(dom0_xe "template-list name-label='${name}' params=uuid --minimal" 2>/dev/null | tr -d '\r')
    [[ -n "$found" ]]
}

# --- Guest preparation scripts ---------------------------------------------
#
# One function per distribution family, emitting the script that runs *inside*
# the guest on its single boot. These do the work that cannot be done from the
# outside: install the guest agent, then scrub the identity the clone must
# generate fresh.
#
# Every one of them must end by powering the VM off. The build waits for the
# VM to halt as its signal that preparation finished, so a script that returns
# without shutting down hangs the build until the timeout.

# Emit the in-guest preparation script for Debian and derivatives.
#
# The guest tools come from the ISO rather than apt. Debian 13 has no
# xe-guest-utilities package -- the apt path fails with "unable to locate", and
# silently, because cloud-init does not abort a failed package install -- so
# the ISO is the only route that works there. It is also the route XCP-ng's own
# documentation gives.
tpl_prep_debian() {
    local user="$1"
    # The heredoc is quoted so the guest script is emitted verbatim -- nothing
    # in it should be expanded by this shell. The one value that does have to
    # be substituted is the account name, done here rather than by unquoting
    # the heredoc and risking every $ in the script expanding too.
    cat <<'PREP_EOF' | sed "s/__TPL_USER__/${user}/g"
#!/bin/bash
# Prepares a cloud image for use as an XCP-ng template. Runs once, inside the
# guest, then powers the VM off.
exec > /var/log/xo-template-prep.log 2>&1
set -x

export DEBIAN_FRONTEND=noninteractive

# --- guest tools ---
# From the ISO: the distro package does not exist on every release, and when it
# is missing apt fails without stopping cloud-init, which produces a template
# that looks fine and never reports an IP.
install_guest_tools() {
    local mnt=/mnt
    if ! mountpoint -q "$mnt" && mount /dev/cdrom "$mnt" 2>/dev/null; then
        if [[ -f "$mnt/Linux/install.sh" ]]; then
            bash "$mnt/Linux/install.sh" -n
            umount "$mnt" 2>/dev/null || true
            return 0
        fi
        umount "$mnt" 2>/dev/null || true
    fi
    # Fallback for images whose release does package it.
    apt-get install -y xe-guest-utilities || true
}
install_guest_tools

# --- cloud-init and disk growth ---
# growroot is what lets the operator ask for a bigger disk than the image at
# deploy time and have the filesystem actually fill it.
apt-get update -qq || true
apt-get install -y cloud-init cloud-initramfs-growroot || true

# --- shipped login ---
# The template carries a known password so a freshly deployed VM is reachable
# without the operator having to supply a cloud-config first. This matches how
# the equivalent Hub templates behave; anyone wanting key-only access supplies
# ssh_authorized_keys at VM creation and can lock the password afterwards.
echo "__TPL_USER__:__TPL_USER__" | chpasswd
printf 'PasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/99-xo-template.conf

# --- scrub machine identity ---
# Everything below this line exists so that clones do not share an identity.
# Skipping any of it produces VMs that collide on the network: a shared
# machine-id breaks DHCP leases and systemd journals, and shared host keys mean
# every VM presents the same SSH fingerprint.
cloud-init clean --logs --seed
rm -rf /var/lib/cloud/instances /var/lib/cloud/instance
rm -f /var/log/cloud-init.log /var/log/cloud-init-output.log
truncate -s 0 /etc/machine-id
truncate -s 0 /var/lib/dbus/machine-id 2>/dev/null || true
find /etc/ssh -type f -name 'ssh_host_*' -delete
apt-get clean
rm -f /root/.bash_history /home/*/.bash_history

# The build watches for the VM to halt. This must be the last thing that runs.
shutdown -h now
PREP_EOF
}
# Decide whether a VDI actually holds a disk image, by reading its first sector.
#
# This replaces a check on physical-utilisation, which cannot answer the
# question: on a thin SR that number is allocated blocks, and XAPI imports raw
# images with vhd-tool's --prezeroed on anything that is not lvm/lvmoiscsi/
# lvmohba, so zero blocks are skipped rather than written. A correctly imported
# cloud image can therefore allocate a few kilobytes and be entirely intact.
#
# The disk is read over XAPI's /export_raw_vdi endpoint with a ranged GET.
# There is no `xe vdi-attach` -- VDI.attach is an API call the CLI does not
# expose -- and attaching to dom0 would in any case have to be undone before
# the VBD could be plugged into the build VM. A range request touches nothing
# and transfers one kilobyte.
#
# Every image in the catalogue is a whole-disk image, so sector 0 carries either
# an MBR (the 0x55AA signature at offset 510) or a protective MBR in front of a
# GPT ("EFI PART" at offset 512). Absence of both means nothing usable landed.
tpl_disk_has_partition_table() {
    local vdi="$1"
    local vdi_ref sig=""

    if ! vdi_ref=$(deploy_vdi_ref "$vdi"); then
        # Inconclusive, not failed: refusing a build over a check that could
        # not run is the mistake this function exists to undo.
        log_warning "  could not resolve the disk to verify it; skipping the check."
        return 0
    fi

    # The read must be capped on the pool master, not by asking politely for a
    # range. /export_raw_vdi has no Range handling at all (export_raw_vdi.ml
    # answers a plain 200 and streams the whole disk), so `curl -r 0-1023`
    # is ignored and the entire VDI comes back -- 8 GiB, expanded about
    # three-and-a-half times by `od`, into a command substitution. Bash tries to
    # hold the result in a single string and segfaults. `head -c` in front of od
    # bounds it at one kilobyte, and closing the pipe stops curl at once.
    #
    # od rather than xxd: xxd is not on a stock XCP-ng dom0.
    sig=$(dom0_exec "curl -sk -f --max-time 120 \
        'https://localhost/export_raw_vdi?session_id=${DEPLOY_SESSION}&vdi=${vdi_ref}&format=raw' \
        2>/dev/null | head -c 1024 | od -An -tx1 -v | tr -d ' \n'")

    if (( ${#sig} < 1040 )); then
        log_warning "  could not read the disk to verify it; skipping the check."
        return 0
    fi

    # MBR signature 0x55AA lives at offset 510, i.e. hex characters 1020..1023.
    [[ "${sig:1020:4}" == "55aa" ]] && return 0

    # A GPT disk still carries a protective MBR, so the check above normally
    # catches it; this covers an image written with a bare GPT header.
    # "EFI PART" == 4546492050415254, at offset 512 (hex characters 1024..).
    [[ "${sig:1024:16}" == "4546492050415254" ]] && return 0

    return 1
}
# Decide which boot firmware a template should advertise, by looking for an EFI
# system partition on the disk that was actually imported.
#
# This is not a property of the distribution, it is a property of the image, and
# the two do not track each other: an image can be perfectly good and still have
# nothing for UEFI firmware to load. So it is read off the disk rather than
# assumed, per image, every build. If a future catalogue entry ships a BIOS-only
# image, it gets a BIOS template without anyone having to remember to say so.
#
# UEFI is preferred when the disk supports it. It is what XO's own Hub templates
# end up being used as, it is required for Secure Boot and a vTPM, and the
# images that carry an ESP carry a BIOS boot partition beside it -- so an
# operator who wants BIOS still gets a working VM by choosing it in the same
# dropdown. When no ESP is present the template must say bios: UEFI firmware
# with no bootloader to load does not fall back, it simply fails to boot.
#
# GPT is read from the disk over the same export the partition-table check uses.
# The partition array starts at LBA 2 by default and each entry is 128 bytes,
# and a partition's type is the first 16 bytes as a mixed-endian GUID. The ESP
# type is C12A7328-F81F-11D2-BA4B-00A0C93EC93B, which on the wire is the byte
# sequence 28732AC11FF8D211BA4B00A0C93EC93B.
#
# Reading only the first sectors is what produced a wrong answer once already:
# a 32 KiB window truncates the 16 KiB partition array often enough to miss the
# ESP entirely and report an image as BIOS-only when it is not. 40 KiB covers
# LBA 2 through the whole 128-entry array with room to spare.
TPL_ESP_GUID_LE="28732ac11ff8d211ba4b00a0c93ec93b"

tpl_disk_supports_uefi() {
    local vdi="$1"
    local vdi_ref sig=""

    deploy_vdi_ref "$vdi" >/dev/null 2>&1 || return 1
    vdi_ref=$(deploy_vdi_ref "$vdi")

    sig=$(dom0_exec "curl -sk -f --max-time 180 \
        'https://localhost/export_raw_vdi?session_id=${DEPLOY_SESSION}&vdi=${vdi_ref}&format=raw' \
        2>/dev/null | head -c 40960 | od -An -tx1 -v | tr -d ' \n'")

    # No GPT at all means no ESP. "EFI PART" at offset 512.
    [[ "${sig:1024:16}" == "4546492050415254" ]] || return 1

    # The partition array is scanned as a whole rather than entry by entry:
    # the type GUID is at a fixed offset inside each 128-byte entry, but a
    # substring search over the array finds it wherever the entry sits, and the
    # GUID is long enough that a false positive is not a practical concern.
    [[ "$sig" == *"${TPL_ESP_GUID_LE}"* ]]
}


tpl_find_tools_iso() {
    # Exact name only. Pools accumulate "Old version of guest-tools.iso"
    # alongside the current one, and a substring match would return several
    # uuids -- which `vm-cd-insert cd-name=` then rejects as ambiguous.
    local vdi
    vdi=$(dom0_xe "vdi-list name-label='${TPL_TOOLS_ISO_NAME}' params=uuid --minimal" 2>/dev/null | tr -d '\r' | cut -d',' -f1)
    printf '%s' "$vdi"
}

# Attach the guest tools ISO to the build VM.
#
# The base template provisions no CD drive, so there is nothing for
# `vm-cd-insert` to insert into -- it has to be created first. Attaching the
# VDI by uuid rather than by name also sidesteps the duplicate-name problem
# entirely.
tpl_attach_tools_iso() {
    local vdi="$1"

    # An empty CD VBD. `type=CD mode=RO` with no VDI is how xe models a drive
    # with no disc in it; `vbd-insert` then loads one.
    local cd_vbd
    cd_vbd=$(dom0_xe "vbd-create vm-uuid=${TPL_VM_UUID} device=3 type=CD mode=RO" 2>/dev/null | tr -d '\r')
    if [[ -z "$cd_vbd" ]]; then
        return 1
    fi

    dom0_xe "vbd-insert uuid=${cd_vbd} vdi-uuid=${vdi}" >/dev/null 2>&1
}

# Build the cloud-init drive that drives the single preparation boot.
#
# This is not the config drive the operator's VMs get -- theirs comes from XO
# at creation time. This one exists only to run the prep script once, and is
# destroyed before the template is sealed so no trace of it is inherited.
tpl_build_prep_drive() {
    local row="$1"
    local user prep_fn
    user=$(tpl_field "$row" 5)
    prep_fn=$(tpl_field "$row" 6)

    local dir="${DEPLOY_WORKDIR}/tpl-cidata"
    rm -rf "$dir"; mkdir -p "$dir"

    # A throwaway key so the build can reach the guest if it has to be
    # diagnosed. It never leaves DEPLOY_WORKDIR and dies with it.
    ssh-keygen -t ed25519 -N "" -C "xo template build (temporary)" \
        -f "${DEPLOY_WORKDIR}/tpl_key" >/dev/null 2>&1
    TPL_SSH_KEY="${DEPLOY_WORKDIR}/tpl_key"
    local pubkey
    pubkey=$(<"${TPL_SSH_KEY}.pub")
    pubkey="${pubkey%$'\n'}"

    printf 'instance-id: xo-template-build\nlocal-hostname: xo-template-build\n' > "${dir}/meta-data"
    : > "${dir}/network-config"

    # The prep script is embedded rather than fetched. A build that reaches out
    # to a git host mid-run fails on an air-gapped pool and silently changes
    # behaviour when the remote does, neither of which belongs in something
    # that produces a golden image.
    {
        printf '#cloud-config\n'
        printf 'users:\n'
        printf '  - name: %s\n' "$user"
        printf '    sudo: ALL=(ALL) NOPASSWD:ALL\n'
        printf '    shell: /bin/bash\n'
        printf '    lock_passwd: false\n'
        printf '    ssh_authorized_keys:\n'
        printf '      - %s\n' "$pubkey"
        printf 'write_files:\n'
        printf '  - path: /root/xo-template-prep.sh\n'
        printf "    permissions: '0755'\n"
        printf '    content: |\n'
        "$prep_fn" "$user" | sed 's/^/      /'
        printf 'runcmd:\n'
        printf '  - [ /root/xo-template-prep.sh ]\n'
    } > "${dir}/user-data"

    local iso="${DEPLOY_WORKDIR}/tpl-cidata.iso"
    rm -f "$iso"
    if command -v genisoimage >/dev/null 2>&1; then
        genisoimage -quiet -output "$iso" -volid cidata -joliet -rock \
            "${dir}/user-data" "${dir}/meta-data" "${dir}/network-config"
    else
        xorriso -as mkisofs -quiet -o "$iso" -V cidata -J -r \
            "${dir}/user-data" "${dir}/meta-data" "${dir}/network-config" 2>/dev/null
    fi
    TPL_CIDATA_ISO="$iso"
}

# Create the VM the template is built from, import the image into it, and boot
# it once so the prep script runs.
tpl_create_build_vm() {
    local row="$1" name="$2"
    local url
    url=$(tpl_field "$row" 4)

    local base
    base=$(dom0_xe "template-list name-label='Other install media' params=uuid --minimal" | tr -d '\r')
    if [[ -z "$base" ]]; then
        log_error "Could not find the 'Other install media' template on this host."
        return 1
    fi

    # Named so it reads as a step in progress rather than a VM someone
    # abandoned: it is visible in XO for the few minutes the preparation boot
    # takes, and on failure it is deliberately left behind for its log.
    TPL_VM_UUID=$(dom0_xe "vm-install template=${base} new-name-label='[building template] ${name}' sr-uuid=${DEPLOY_SR_UUID}" | tr -d '\r')
    if [[ -z "$TPL_VM_UUID" ]]; then
        log_error "Failed to create the build VM."
        return 1
    fi
    TPL_BUILD_STARTED="true"

    # Drop any disk the base template provisioned so device 0 is free.
    local vbd vdi
    for vbd in $(dom0_xe "vbd-list vm-uuid=${TPL_VM_UUID} type=Disk params=uuid --minimal" | tr ',' ' '); do
        [[ -n "$vbd" ]] || continue
        vdi=$(dom0_xe "vbd-param-get uuid=${vbd} param-name=vdi-uuid" 2>/dev/null | tr -d '\r' || echo "")
        dom0_xe "vbd-destroy uuid=${vbd}" >/dev/null 2>&1 || true
        [[ -n "$vdi" && "$vdi" != "<not in database>" ]] && dom0_xe "vdi-destroy uuid=${vdi}" >/dev/null 2>&1 || true
    done

    local mem="${TPL_DEFAULT_RAM_GB}GiB"
    dom0_xe "vm-param-set uuid=${TPL_VM_UUID} VCPUs-max=${TPL_DEFAULT_VCPUS}" >/dev/null
    dom0_xe "vm-param-set uuid=${TPL_VM_UUID} VCPUs-at-startup=${TPL_DEFAULT_VCPUS}" >/dev/null

    # Present the vCPUs as cores on one socket rather than a socket each.
    #
    # The base template leaves cores-per-socket at 1, so a 2-vCPU VM arrives as
    # a two-socket machine. Guests licence and schedule per socket, and every
    # VM on a live pool that was not built from this path has
    # cores-per-socket equal to its vCPU count.
    dom0_xe "vm-param-set uuid=${TPL_VM_UUID} platform:cores-per-socket=${TPL_DEFAULT_VCPUS}" >/dev/null 2>&1 || true

    # Viridian is Hyper-V enlightenment, for Windows guests. The
    # "Other install media" base template turns it on, and nothing in this build
    # turned it back off, so every template produced here advertised itself to
    # Linux as a Hyper-V machine. Surveyed against a live pool: the only VMs
    # with viridian enabled are the Windows ones and the ones this script built.
    dom0_xe "vm-param-set uuid=${TPL_VM_UUID} platform:viridian=false" >/dev/null 2>&1 || true
    dom0_xe "vm-memory-limits-set uuid=${TPL_VM_UUID} static-min=${mem} dynamic-min=${mem} dynamic-max=${mem} static-max=${mem}" >/dev/null

    # Firmware for the *build*: BIOS, always, whatever the finished template
    # ends up advertising.
    #
    # A UEFI guest writes its boot entries into its own NVRAM on first boot.
    # Building under UEFI would bake this build VM's entries into the template,
    # where they are at best redundant and at worst point at a disk layout the
    # clone does not have. BIOS reads the disk directly and records nothing.
    # tpl_seal_template sets the firmware the operator is offered, after this
    # boot has happened.
    dom0_xe "vm-param-set uuid=${TPL_VM_UUID} HVM-boot-policy='BIOS order'" >/dev/null
    dom0_xe "vm-param-set uuid=${TPL_VM_UUID} HVM-boot-params:order=cd" >/dev/null

    # A standard VGA device with 8 MiB behind it, in place of the stock 4 MiB
    # cirrus adapter that leaves XO's console at 640x480.
    #
    # Both halves are needed, and 8 is the number. Setting vga=std alone leaves
    # videoram at whatever the base template carried, which is 4 -- checked on a
    # live pool, a template built that way came out std/4 and its UEFI VMs had
    # an unreadable console. 16 is no better: it renders as coloured noise under
    # UEFI. Every working UEFI VM on that pool runs std with 8. XAPI accepts any
    # of these without complaint, so a wrong value fails silently and only shows
    # up on the console.
    dom0_xe "vm-param-set uuid=${TPL_VM_UUID} platform:vga=std" >/dev/null 2>&1 || true
    dom0_xe "vm-param-set uuid=${TPL_VM_UUID} platform:videoram=8" >/dev/null 2>&1 || true

    log_info "  creating the root disk..."
    TPL_ROOT_VDI=$(dom0_xe "vdi-create sr-uuid=${DEPLOY_SR_UUID} name-label='${name} root' virtual-size=${TPL_DEFAULT_DISK_GB}GiB type=user" | tr -d '\r')
    if [[ ! "$TPL_ROOT_VDI" =~ ^[0-9a-f-]{36}$ ]]; then
        # Anything but a uuid here -- an error string, an empty line -- becomes
        # a malformed import URL further down, where the endpoint accepts the
        # connection, writes a few kilobytes and stops. That failure reads as a
        # sizing problem rather than a bad reference, so it is caught here.
        log_error "  the pool master did not return a disk uuid: ${TPL_ROOT_VDI:-<empty>}"
        return 1
    fi
    dom0_xe "vbd-create vm-uuid=${TPL_VM_UUID} vdi-uuid=${TPL_ROOT_VDI} device=0 bootable=true type=Disk mode=RW" >/dev/null

    log_info "  importing the cloud image (this is the longest step)..."
    log_info "    ${url}"
    if ! deploy_import_vdi_from_url "$TPL_ROOT_VDI" "$url"; then
        log_error "Failed to import the cloud image."
        return 1
    fi

    # Confirm the image actually landed, by reading what is on the disk rather
    # than by how much of it the SR has allocated.
    #
    # physical-utilisation is not a measure of bytes written. On a thin SR it
    # reports allocated blocks, and XAPI imports a raw image with vhd-tool's
    # --prezeroed flag on any SR that is not lvm/lvmoiscsi/lvmohba
    # (sm_fs_ops.ml: must_write_zeroes_into_new_vdi), which skips zero blocks
    # instead of writing them. A cloud image is a partition table, a bootloader
    # and a mostly empty filesystem, so a *correct* import of one allocates
    # almost nothing: the Debian 13 image lands at 19456 bytes on thin NFS, and
    # a Debian cloud image imported by other means sits at 11264 on the same
    # pool. A byte threshold therefore condemns every successful import on thin
    # storage -- which it did, on every run, while the imports were fine.
    #
    # What distinguishes an imported disk from a blank one is its content. The
    # first sector of any of these images carries a partition table, so attach
    # the disk to dom0 and ask for it. That is true regardless of SR type,
    # allocation policy or how sparse the image happens to be.
    if ! tpl_disk_has_partition_table "$TPL_ROOT_VDI"; then
        log_error "  the image import reported success but the disk has no"
        log_error "  partition table, so nothing usable was written to it."
        local vsize sr_uuid sr_type used
        vsize=$(dom0_xe "vdi-param-get uuid=${TPL_ROOT_VDI} param-name=virtual-size" 2>/dev/null | tr -d '\r')
        sr_uuid=$(dom0_xe "vdi-param-get uuid=${TPL_ROOT_VDI} param-name=sr-uuid" 2>/dev/null | tr -d '\r')
        sr_type=$(dom0_xe "sr-param-get uuid=${sr_uuid} param-name=type" 2>/dev/null | tr -d '\r')
        used=$(dom0_xe "vdi-param-get uuid=${TPL_ROOT_VDI} param-name=physical-utilisation" 2>/dev/null | tr -d '\r')
        log_error "  disk ${TPL_ROOT_VDI}"
        log_error "    virtual-size ${vsize:-unknown}, allocated ${used:-unknown}"
        log_error "    SR ${sr_uuid:-unknown} (type ${sr_type:-unknown})"
        log_error "  XAPI logs the import on the pool master:"
        log_error "    ssh ${HOST_USERNAME}@${POOL_MASTER_IP} grep -i vhd-tool /var/log/xensource.log"
        return 1
    fi
    log_success "  image imported and checksum verified"

    # The prep drive.
    TPL_CIDATA_VDI=$(dom0_xe "vdi-create sr-uuid=${DEPLOY_SR_UUID} name-label='${name} cidata' virtual-size=16MiB type=user" | tr -d '\r')
    if ! deploy_import_vdi_from_file "$TPL_CIDATA_VDI" "$TPL_CIDATA_ISO"; then
        log_error "Failed to import the preparation config drive."
        return 1
    fi
    dom0_xe "vbd-create vm-uuid=${TPL_VM_UUID} vdi-uuid=${TPL_CIDATA_VDI} device=1 type=Disk mode=RO" >/dev/null

    # The guest tools ISO, mounted for the prep script to install from.
    local tools_vdi
    tools_vdi=$(tpl_find_tools_iso)
    if [[ -z "$tools_vdi" ]]; then
        # Fatal rather than a warning. On Debian 13 there is no
        # xe-guest-utilities package for the prep script to fall back to, so
        # without the ISO the build produces a template whose VMs never report
        # an IP -- which looks like success and is discovered much later.
        log_error "  ${TPL_TOOLS_ISO_NAME} was not found on this pool."
        log_error "  It normally lives in the 'XCP-ng Tools' storage repository."
        log_error "  Without it the guest agent cannot be installed and XO would"
        log_error "  never report an IP address for VMs built from this template."
        return 1
    fi

    if ! tpl_attach_tools_iso "$tools_vdi"; then
        log_error "  could not attach ${TPL_TOOLS_ISO_NAME} to the build VM."
        return 1
    fi

    dom0_xe "vif-create vm-uuid=${TPL_VM_UUID} network-uuid=${DEPLOY_NETWORK_UUID} device=0" >/dev/null

    log_info "  booting once to install the guest agent and scrub machine state..."
    log_info "  (this takes a few minutes and the VM powers itself off when done)"
    dom0_xe "vm-start uuid=${TPL_VM_UUID}" >/dev/null
    return 0
}

# Wait for the preparation boot to finish. The prep script ends in a shutdown,
# so the VM halting is the completion signal -- there is no need to reach into
# the guest, and nothing to reach it over once the host keys are deleted.
tpl_wait_for_prep() {
    local timeout="${1:-900}"
    local waited=0 interval=15 state=""

    # Wait for the VM to actually start before watching for it to stop.
    #
    # Without this the loop below reads "halted" on its first pass -- XAPI has
    # not necessarily moved the VM out of that state by the time vm-start
    # returns -- and treats a VM that never booted as a finished preparation.
    # The template then seals with no guest agent installed and no machine
    # state scrubbed, which looks exactly like success.
    local starting=0
    while (( starting < 120 )); do
        state=$(dom0_xe "vm-param-get uuid=${TPL_VM_UUID} param-name=power-state" 2>/dev/null | tr -d '\r')
        [[ "$state" == "running" ]] && break
        sleep 5
        starting=$((starting + 5))
    done
    if [[ "$state" != "running" ]]; then
        log_error "The build VM did not start (power state: ${state:-unknown})."
        return 1
    fi

    # Watch for the guest agent while the VM is still up.
    #
    # PV-drivers-version is populated by the agent from inside the guest and
    # cleared when the domain goes away, so it cannot be read after the
    # preparation boot -- which deliberately ends with the VM powering itself
    # off. Observing it here, in the poll that is already running, is therefore
    # the only way to see it at all. It is a *secondary* signal: on this pool
    # every halted VM reports it empty, working ones included, and on guest
    # tools that ship the management agent without versioned PV drivers it may
    # never appear even while running. tpl_build_one's check does not depend
    # on it.
    TPL_AGENT_SEEN=""
    local pv=""
    while (( waited < timeout )); do
        state=$(dom0_xe "vm-param-get uuid=${TPL_VM_UUID} param-name=power-state" 2>/dev/null | tr -d '\r')
        if [[ -z "$TPL_AGENT_SEEN" && "$state" == "running" ]]; then
            pv=$(dom0_xe "vm-param-get uuid=${TPL_VM_UUID} param-name=PV-drivers-version" 2>/dev/null | tr -d '\r')
            [[ "$pv" =~ [0-9]+\.[0-9]+ ]] && TPL_AGENT_SEEN="$pv"
        fi
        if [[ "$state" == "halted" ]]; then
            return 0
        fi
        # Poll quickly until the agent has been seen, then back off.
        if [[ -n "$TPL_AGENT_SEEN" ]]; then
            sleep "$interval"
        else
            sleep 5
            waited=$((waited - interval + 5))
        fi
        waited=$((waited + interval))
        if (( waited % 120 == 0 )); then
            log_info "    still preparing (${waited}s elapsed)..."
        fi
    done

    log_error "The preparation boot did not finish within ${timeout}s."
    log_error "The VM '${TPL_VM_NAME:-build}' is left running for inspection:"
    log_error "  its prep log is at /var/log/xo-template-prep.log inside the guest."
    return 1
}

# Strip the build scaffolding and seal the VM as a template.
tpl_seal_template() {
    local name="$1"

    # The preparation drive must not survive into the template: cloud-init
    # would find a used seed on every clone and skip the operator's own config.
    local vbd
    for vbd in $(dom0_xe "vbd-list vm-uuid=${TPL_VM_UUID} type=Disk params=uuid --minimal" | tr ',' ' '); do
        [[ -n "$vbd" ]] || continue
        local vdi
        vdi=$(dom0_xe "vbd-param-get uuid=${vbd} param-name=vdi-uuid" 2>/dev/null | tr -d '\r' || echo "")
        if [[ "$vdi" == "$TPL_CIDATA_VDI" ]]; then
            dom0_xe "vbd-destroy uuid=${vbd}" >/dev/null 2>&1 || true
            dom0_xe "vdi-destroy uuid=${vdi}" >/dev/null 2>&1 || true
        fi
    done
    TPL_CIDATA_VDI=""

    dom0_xe "vm-cd-eject uuid=${TPL_VM_UUID}" >/dev/null 2>&1 || true

    # The firmware the operator is offered.
    #
    # XO's New VM form takes its "Boot firmware" default straight from the
    # template -- xo-web's new-vm form does
    # `hvmBootFirmware: defined(() => template.boot.firmware, '')`, reading
    # HVM-boot-params:firmware -- so whatever is set here is what someone gets
    # without opening advanced settings. Left unset it reads as BIOS.
    #
    # Which one is right depends on the image, not on the distribution, so it is
    # decided by looking at the disk that was actually imported: UEFI when it
    # carries an EFI system partition, BIOS when it does not. Set after the
    # build boot, which always runs under BIOS, so no NVRAM from this VM is
    # baked into the template.
    if tpl_disk_supports_uefi "$TPL_ROOT_VDI"; then
        dom0_xe "vm-param-set uuid=${TPL_VM_UUID} HVM-boot-params:firmware=uefi" >/dev/null 2>&1 || true
        log_info "  the image carries an EFI system partition; publishing as UEFI."
    else
        dom0_xe "vm-param-set uuid=${TPL_VM_UUID} HVM-boot-params:firmware=bios" >/dev/null 2>&1 || true
        log_info "  the image has no EFI system partition; publishing as BIOS."
    fi

    dom0_xe "vm-param-set uuid=${TPL_VM_UUID} name-label='${name}'" >/dev/null
    dom0_xe "vm-param-set uuid=${TPL_VM_UUID} name-description='${TPL_DESCRIPTION}'" >/dev/null

    # XO's VM General tab reads other-config:base_template_name to show what a
    # VM was built from. Left as the scaffolding it happens to have been built
    # on, every VM cloned from this template reports "Other install media"
    # instead of the template the operator actually picked. Cosmetic -- the
    # field only steers behaviour on the PV install path, which an HVM guest
    # never takes -- but it is the field someone reads to answer that question.
    dom0_xe "vm-param-set uuid=${TPL_VM_UUID} other-config:base_template_name='${name}'" >/dev/null 2>&1 || true
    dom0_xe "vm-param-set uuid=${TPL_VM_UUID} is-a-template=true" >/dev/null

    return 0
}

# Remove a half-built VM. Called when a build fails partway: the wreckage is a
# VM with a multi-gigabyte disk attached, which is worth clearing rather than
# leaving for the operator to identify and unpick by hand.
tpl_cleanup_failed_build() {
    [[ "$TPL_BUILD_STARTED" == "true" ]] || return 0
    [[ -n "$TPL_VM_UUID" ]] || return 0

    local state
    state=$(dom0_xe "vm-param-get uuid=${TPL_VM_UUID} param-name=power-state" 2>/dev/null | tr -d '\r')
    if [[ "$state" == "running" || "$state" == "paused" ]]; then
        dom0_xe "vm-shutdown --force uuid=${TPL_VM_UUID}" >/dev/null 2>&1 || true
    fi
    # Destroys the VM and every disk that came with it.
    dom0_xe "vm-uninstall --force uuid=${TPL_VM_UUID}" >/dev/null 2>&1 || true

    TPL_VM_UUID=""; TPL_ROOT_VDI=""; TPL_CIDATA_VDI=""; TPL_BUILD_STARTED="false"
}

# Build one template: one image, one firmware mode, start to finish.
tpl_build_one() {
    local row="$1"
    local key display user
    key=$(tpl_field "$row" 1)
    display=$(tpl_field "$row" 2)
    user=$(tpl_field "$row" 5)

    local name
    name=$(tpl_template_name "$display")

    echo ""
    log_info "Building: ${name}"

    if tpl_template_exists "$name"; then
        log_info "  a template named '${name}' already exists; skipping."
        return 0
    fi

    # Shown in XO under the template name. Says what the operator needs to know
    # to actually log in to a VM built from it.
    TPL_DESCRIPTION="${display} with cloud-init and XCP-ng guest tools. Boots under BIOS or UEFI. Default login: ${user} / ${user}. Supply an SSH key or your own cloud-config at VM creation."
    TPL_VM_NAME="$name"

    TPL_VM_UUID=""; TPL_ROOT_VDI=""; TPL_CIDATA_VDI=""; TPL_BUILD_STARTED="false"

    tpl_build_prep_drive "$row"

    if ! tpl_create_build_vm "$row" "$name"; then
        # Everything up to the preparation boot is reproducible, so the
        # wreckage -- a VM with a multi-gigabyte disk -- is cleared rather than
        # left for the operator to identify and unpick.
        tpl_cleanup_failed_build
        return 1
    fi

    if ! tpl_wait_for_prep 900; then
        # Deliberately not cleaned up: the guest holds the prep log that says
        # why it failed, and destroying it would take the evidence with it.
        TPL_BUILD_STARTED="false"
        return 1
    fi

    # Prove the preparation actually happened before sealing.
    #
    # A VM that boots and halts is not evidence the prep ran: a kernel panic,
    # a cloud-init failure or a config drive the guest never read all end the
    # same way. XAPI records the guest agent's version only when the agent has
    # run inside the VM, so its presence is the one signal visible from the
    # host that says the preparation boot did what it was for.
    # The signal is os-version, not PV-drivers-version.
    #
    # Both are written by the guest agent from inside the VM, so either one
    # proves it ran -- but they do not survive shutdown alike. XAPI clears
    # PV-drivers-version when the domain goes away, while os-version and the
    # reported addresses persist. Checked against a live pool: every halted VM
    # there reports PV-drivers-version empty, working ones included, and a
    # correctly prepared build VM shows os-version
    # "Debian GNU/Linux 13 (trixie)" with a kernel string beside it. Guest
    # tools that ship the management agent without versioned PV drivers may
    # also never populate PV-drivers-version at all, even while running.
    #
    # So the check reads os-version off the halted VM, which is exactly the
    # state tpl_wait_for_prep leaves it in. TPL_AGENT_SEEN, recorded during the
    # boot, is accepted as corroboration when it happens to have been caught.
    # Requiring an empty-string test would pass on a VM with no agent at all,
    # so the check is for a distro name -- something only the agent supplies.
    local osv
    osv=$(dom0_xe "vm-param-get uuid=${TPL_VM_UUID} param-name=os-version" 2>/dev/null | tr -d '\r')
    if [[ ! "$osv" =~ [A-Za-z] ]] || [[ "$osv" == "<not in database>" ]]; then
        osv=""
    fi
    if [[ -z "$osv" && ! "${TPL_AGENT_SEEN:-}" =~ [0-9]+\.[0-9]+ ]]; then
        log_error "  the preparation boot finished, but the guest agent is not"
        log_error "  installed -- so XO would never report an IP for VMs built"
        log_error "  from this template."
        log_error "  The build VM is left in place; its log is at"
        log_error "  /var/log/xo-template-prep.log inside it."
        TPL_BUILD_STARTED="false"
        return 1
    fi

    if ! tpl_seal_template "$name"; then
        tpl_cleanup_failed_build
        return 1
    fi

    TPL_BUILD_STARTED="false"
    log_success "  ${name} is ready"
    return 0
}

# --- Selection --------------------------------------------------------------

# The template library submenu.
#
# Driven by the same keys as the main menu — arrows to move, space to select,
# enter to confirm — rather than a numbered prompt, so the two do not teach
# different habits for the same job. Multi-select: everything ticked is built
# in one run.
#
# It draws its own rows rather than reusing draw_menu, which is bound to the
# main menu's two-column grid and its parallel MENU_* arrays. A catalogue that
# grows one row per distribution wants a plain list.
tpl_prompt_selection() {
    local count=${#TPL_CATALOG[@]}
    local -a picked
    local i
    for ((i = 0; i < count; i++)); do picked[i]=0; done

    local cursor=0

    # Terminal state is restored on every exit path, including the ones that
    # leave through `return`: a submenu that swallows the cursor or leaves echo
    # off makes the whole script look hung afterwards.
    local saved_tpl_stty
    saved_tpl_stty=$(stty -g 2>/dev/null) || saved_tpl_stty=""
    menu_hide_cursor
    stty -echo 2>/dev/null || true
    _tpl_restore_term() {
        menu_show_cursor
        [[ -n "$saved_tpl_stty" ]] && stty "$saved_tpl_stty" 2>/dev/null || stty echo 2>/dev/null
    }

    local row display user
    while true; do
        clear
        echo ""
        printf '  %sVM Template Library%s\n' "$M_BOLD" "$M_RESET"
        echo ""
        printf '  %sCloud-init templates built from each distribution'"'"'s own published%s\n' "$M_DIM" "$M_RESET"
        printf '  %simage. Once built they appear in Xen Orchestra under New -> VM.%s\n' "$M_DIM" "$M_RESET"
        echo ""

        for ((i = 0; i < count; i++)); do
            row="${TPL_CATALOG[$i]}"
            display=$(tpl_field "$row" 2)
            user=$(tpl_field "$row" 5)

            local mark="[ ]"
            [[ ${picked[$i]} -eq 1 ]] && mark="[${M_GREEN}✓${M_RESET}]"

            local pointer="  "
            local label="$display"
            if (( i == cursor )); then
                pointer="${M_CYAN}▸${M_RESET} "
                label="${M_BOLD}${display}${M_RESET}"
            fi

            printf '  %s%s %s %s(login: %s)%s\n' \
                "$pointer" "$mark" "$label" "$M_DIM" "$user" "$M_RESET"

            # Say plainly which of these already exist, so a re-run is not a
            # guess about what a build would actually do.
            if tpl_template_exists "$(tpl_template_name "$display")"; then
                printf '       %salready on this pool%s\n' "$M_DIM" "$M_RESET"
            fi
        done

        echo ""
        local n_sel=0
        for ((i = 0; i < count; i++)); do (( picked[i] == 1 )) && n_sel=$((n_sel + 1)); done
        printf '  %sSelected: %d%s\n' "$M_DIM" "$n_sel" "$M_RESET"
        echo ""
        printf '  %s↑↓ Navigate   SPACE Select/Deselect   ENTER Confirm   Q Back%s\n' "$M_DIM" "$M_RESET"

        menu_read_key
        case "$MENU_KEY" in
            UP)
                if (( cursor == 0 )); then cursor=$((count - 1)); else cursor=$((cursor - 1)); fi
                ;;
            DOWN)
                cursor=$(( (cursor + 1) % count ))
                ;;
            SPACE)
                picked[$cursor]=$(( 1 - picked[cursor] ))
                ;;
            ENTER)
                break
                ;;
            QUIT)
                # Backing out is a normal outcome, not a failure: returning
                # non-zero here would be caught by the script's ERR trap and
                # printed as an error. The empty selection is the signal.
                _tpl_restore_term
                clear
                TPL_SELECTED=()
                return 0
                ;;
        esac
    done

    _tpl_restore_term
    clear

    TPL_SELECTED=()
    for ((i = 0; i < count; i++)); do
        (( picked[i] == 1 )) && TPL_SELECTED+=("${TPL_CATALOG[$i]}")
    done

    return 0
}

# Clean up after a template build run.
#
# Mirrors deploy_cleanup: closes the shared SSH connection, then removes the
# working directory the prep key and config drive live in.
tpl_cleanup() {
    tpl_cleanup_failed_build
    if [[ -n "${DEPLOY_SSH_CTL:-}" && -S "${DEPLOY_SSH_CTL}" ]]; then
        ssh -o ControlPath="$DEPLOY_SSH_CTL" -O exit \
            "${HOST_USERNAME}@${POOL_MASTER_IP}" 2>/dev/null || true
    fi
    if [[ -n "${DEPLOY_WORKDIR:-}" && -d "$DEPLOY_WORKDIR" ]]; then
        if [[ -f "${DEPLOY_WORKDIR}/tpl_key" ]] && command -v shred >/dev/null 2>&1; then
            shred -u "${DEPLOY_WORKDIR}/tpl_key" 2>/dev/null || true
        fi
        rm -rf "$DEPLOY_WORKDIR"
    fi
}

# Resolve the storage and network the build runs on.
#
# Neither is a user-facing choice here, unlike --deploy where the operator is
# picking where a long-lived VM will live. A template's SR holds only the
# template's own disk, and its network is used once, for the preparation boot --
# both are chosen again in New VM every time a VM is created from it. Prompting
# for them asks the operator to make a decision that does not survive the build.
tpl_resolve_storage() {
    local pool
    pool=$(dom0_xe "pool-list params=uuid --minimal" 2>/dev/null | tr -d '\r' | cut -d',' -f1)
    DEPLOY_SR_UUID=$(dom0_xe "pool-param-get uuid=${pool} param-name=default-SR" 2>/dev/null | tr -d '\r')

    if [[ -z "$DEPLOY_SR_UUID" || "$DEPLOY_SR_UUID" == "<not in database>" ]]; then
        # No default set on the pool. Fall back to the user SR with the most
        # free space rather than failing: any of them can hold the template.
        DEPLOY_SR_UUID=$(dom0_exec 'best=""; bestfree=0
            for u in $(xe sr-list content-type=user params=uuid --minimal | tr "," " "); do
                size=$(xe sr-param-get uuid=$u param-name=physical-size 2>/dev/null)
                used=$(xe sr-param-get uuid=$u param-name=physical-utilisation 2>/dev/null)
                free=$(( size - used ))
                if [ "$free" -gt "$bestfree" ]; then bestfree=$free; best=$u; fi
            done
            echo "$best"' | tr -d '\r')
    fi

    if [[ -z "$DEPLOY_SR_UUID" ]]; then
        log_error "No usable storage repository found on this pool."
        return 1
    fi

    local label
    label=$(dom0_xe "sr-param-get uuid=${DEPLOY_SR_UUID} param-name=name-label" 2>/dev/null | tr -d '\r')
    log_info "Storage: ${label:-$DEPLOY_SR_UUID} (the pool default)"
    return 0
}

# Pick the network the preparation boot uses.
#
# XCP-ng has no "default network" flag, so the management network is the
# closest thing: it carries the pool's own traffic, so it is reachable and has
# DHCP wherever the host does. The prep boot needs an address only long enough
# to install the guest tools from the attached ISO.
tpl_resolve_network() {
    DEPLOY_NETWORK_UUID=$(dom0_xe "pif-list management=true params=network-uuid --minimal" 2>/dev/null | tr -d '\r' | cut -d',' -f1)

    if [[ -z "$DEPLOY_NETWORK_UUID" ]]; then
        DEPLOY_NETWORK_UUID=$(dom0_xe "network-list params=uuid --minimal" 2>/dev/null | tr -d '\r' | cut -d',' -f1)
    fi

    if [[ -z "$DEPLOY_NETWORK_UUID" ]]; then
        log_error "No network found on this pool."
        return 1
    fi

    local label
    label=$(dom0_xe "network-param-get uuid=${DEPLOY_NETWORK_UUID} param-name=name-label" 2>/dev/null | tr -d '\r')
    log_info "Network: ${label:-$DEPLOY_NETWORK_UUID} (the management network)"
    return 0
}

# --- Entry point ------------------------------------------------------------

build_vm_templates() {
    echo ""
    echo "=============================================="
    echo "  Build cloud-init VM templates"
    echo "=============================================="
    echo ""
    echo "  Builds ready-to-use VM templates on your XCP-ng pool from the"
    echo "  distributions' own published cloud images, so 'New VM' in Xen"
    echo "  Orchestra offers them the way XOA's Hub does."
    echo ""
    echo "  A template on XCP-ng is a VM record with its template flag set, so"
    echo "  each one is built by creating a VM, importing the image into it,"
    echo "  booting it once, and then sealing it. The boot is what installs the"
    echo "  XCP-ng guest agent -- without it XO never reports a VM's IP address"
    echo "  -- and what clears the machine-specific state a clone must not"
    echo "  inherit. A VM named '[building template] ...' will appear in XO"
    echo "  while that happens and disappear when it is sealed."
    echo ""
    echo "  Expect roughly five to ten minutes per template, most of it the"
    echo "  image download."
    echo ""
    echo "  Nothing is installed on this machine and your XO install is not"
    echo "  touched; the work happens on the pool."
    echo ""

    deploy_check_local_deps

    tpl_prompt_selection
    if [[ ${#TPL_SELECTED[@]} -eq 0 ]]; then
        log_info "No templates selected."
        return 0
    fi

    # Everything below writes into DEPLOY_WORKDIR -- the SSH control socket, the
    # pinned host key, the generated prep drive -- and the helpers build those
    # paths by interpolation. An unset workdir does not fail loudly: the paths
    # resolve to the filesystem root and the run dies on "Permission denied"
    # from ssh, which reads as a wrong password rather than a missing directory.
    DEPLOY_WORKDIR=$(mktemp -d --tmpdir xo-templates-XXXXXX)
    chmod 700 "$DEPLOY_WORKDIR"
    trap tpl_cleanup EXIT

    # Reuses the deploy path's connection: same pool, same host key pinning,
    # same credentials prompt. Nothing here needs a second way in.
    deploy_connect_pool_master
    tpl_resolve_storage || return 1
    tpl_resolve_network || return 1

    echo ""
    echo "=============================================="
    echo "  Summary"
    echo "=============================================="
    local row
    for row in "${TPL_SELECTED[@]}"; do
        printf '  %s\n' "$(tpl_template_name "$(tpl_field "$row" 2)")"
    done
    echo ""
    local prompt="Build this template?"
    (( ${#TPL_SELECTED[@]} > 1 )) && prompt="Build these ${#TPL_SELECTED[@]} templates?"
    confirm_or_skip "$prompt" || { log_info "Cancelled."; return 0; }

    local built=0 failed=0
    for row in "${TPL_SELECTED[@]}"; do
        if tpl_build_one "$row"; then
            built=$((built + 1))
        else
            failed=$((failed + 1))
            log_error "  build failed; continuing with the rest."
        fi
    done

    echo ""
    echo "=============================================="
    if (( failed == 0 )); then
        log_success "Done. ${built} template(s) ready."
    else
        log_warning "Done. ${built} succeeded, ${failed} failed."
    fi
    echo "=============================================="
    echo ""
    echo "  In Xen Orchestra: New -> VM, then pick one of these templates."
    echo "  Set the name, CPU, memory, disk size and network there; the disk"
    echo "  grows to whatever size you ask for on first boot."
    echo ""
    echo "  Log in with the account named in the template's description, or"
    echo "  supply your own cloud-config at creation time to install an SSH"
    echo "  key and any packages you want."
    echo ""
}

# ============================================================================
# Interactive Menu System
# Provides TUI menu rendering and keyboard navigation
# ============================================================================

# Menu terminal control sequences
M_CSI=$'\x1b['
M_BOLD="${M_CSI}1m"
M_DIM="${M_CSI}2m"
M_RESET="${M_CSI}0m"
M_RED="${M_CSI}31m"
M_GREEN="${M_CSI}32m"
M_YELLOW="${M_CSI}33m"
M_BLUE="${M_CSI}34m"
# M_MAGENTA/M_BLINK complete the ANSI palette but aren't used by the current menu.
# shellcheck disable=SC2034
M_MAGENTA="${M_CSI}35m"
M_CYAN="${M_CSI}36m"
# shellcheck disable=SC2034
M_BLINK="${M_CSI}5m"
M_REVERSE="${M_CSI}7m"

# Menu item names, in draw order: the first half fills the left column top to
# bottom, the second half the right column. With an odd number of items the
# left column gets the extra one and the right column ends a row early. The
# split is computed by menu_derive_layout, so adding an item here is all that is
# needed.
MENU_NAMES=(
    "Install Xen Orchestra"
    "Update Xen Orchestra"
    "Rename Sample-xo-config.cfg"
    "Install XO Proxy"
    "Deploy Xen Orchestra to a new VM"
    "VM Template Library"
    "Reconfigure Xen Orchestra"
    "Rebuild Xen Orchestra"
    "Edit xo-config.cfg"
    "Restore Backup"
    "Adjust Xen Orchestra Memory Allocation"
)
MENU_HINTS=(
    ""
    ""
    ""
    ""
    "(creates the VM for you)"
    "(cloud-init templates for New VM)"
    "(made changes to config)"
    "(wipe & reinstall maintain settings)"
    ""
    ""
    ""
)

MENU_TITLE="Install Xen Orchestra from Sources Setup and Update"

# Derive the grid from the item list rather than writing the counts down a
# second place to drift from. The layout is always two columns: an odd number
# of items gives the extra one to the left column, leaving the right column one
# row short, rather than dropping it into a centered row of its own. Indices run
# down the left column and then down the right, so MENU_NAMES reads in draw
# order. MENU_CENTER_COUNT stays at 0 — the centered row is retained in the
# navigation and drawing code as a no-op path so the two-column grid is the only
# case that can be reached.
menu_derive_layout() {
    MENU_TOTAL=${#MENU_NAMES[@]}
    MENU_LEFT_COUNT=$(( (MENU_TOTAL + 1) / 2 ))
    MENU_RIGHT_COUNT=$(( MENU_TOTAL - MENU_LEFT_COUNT ))
    MENU_CENTER_COUNT=0
}
menu_derive_layout

MENU_CURSOR=0
MENU_SELECTED=()
for ((_menu_i = 0; _menu_i < MENU_TOTAL; _menu_i++)); do
    MENU_SELECTED[_menu_i]=0
done
unset _menu_i
MCOL=0
MROW=0
# Last key read by menu_read_key (set as a global so the read can stay out of a
# subshell — see menu_read_key)
MENU_KEY=""

# Set by the SIGWINCH trap; polled by menu_read_key
MENU_RESIZED=0

# How long menu_read_key waits before letting a pending SIGWINCH trap run. Also
# the worst-case delay between resizing the window and seeing the reflow.
MENU_READ_TIMEOUT=0.2

# Blank columns between the two menu columns
MENU_COL_GAP=4

# Layout state, recomputed from the terminal size on every draw by
# menu_compute_layout. Nothing here is a fixed dimension: the menu shrinks by
# dropping detail (hints, branch names, the banner box, spacer rows) rather than
# by letting lines run off the right edge.
ML_TERM_W=80        # terminal width in columns
ML_TERM_H=24        # terminal height in rows
ML_CONTENT_W=84     # width of the drawn block
ML_COL_W=42         # left column width, two-column mode only
ML_TWO_COL=1        # 1 = two columns, 0 = single stacked column
ML_HINTS=1          # 1 = show the dim hint text after an item name
ML_BRANCHES=1       # 1 = show "(Branch: x)" in the header info block
ML_BANNER=1         # 1 = boxed banner, 0 = plain one-line title
ML_LEGEND=1         # 1 = show the key legend
ML_BLANKS=1         # 1 = show blank spacer rows
ML_TOO_SMALL=0      # 1 = terminal cannot fit even the minimal layout
ML_MIN_W=0          # minimum usable width, reported when ML_TOO_SMALL=1
ML_MIN_H=0          # minimum usable height, reported when ML_TOO_SMALL=1
ML_INFO_LABELS=()   # header info labels, built by menu_compute_layout
ML_INFO_VALUES=()   # header info values, matching ML_INFO_LABELS

# Truncated result from menu_truncate
MTRUNC=""

# Truncate a plain (escape-free) string to at most $2 columns, marking the cut
# with an ellipsis. Result goes to $MTRUNC rather than stdout so the draw loop
# does not fork a subshell per item. Bash string length is character-based under
# a UTF-8 locale, which matches display width for every glyph this menu uses.
menu_truncate() {
    local s="$1" max="$2"
    if (( max <= 0 )); then
        MTRUNC=""
    elif (( ${#s} <= max )); then
        MTRUNC="$s"
    elif (( max == 1 )); then
        MTRUNC="…"
    else
        MTRUNC="${s:0:max-1}…"
    fi
}
MENU_SCRIPT_COMMIT="N/A"
MENU_SCRIPT_MASTER="N/A"
MENU_XO_COMMIT="N/A"
MENU_XO_MASTER="N/A"
# Commit count the install trails master by; appended to the Master XO Commit
# line only when non-empty (i.e. only when behind). Not a separate menu row.
MENU_XO_BEHIND=""
MENU_NODE_VERSION="N/A"

# Hide/show cursor
menu_hide_cursor() { printf "${M_CSI}?25l"; }
menu_show_cursor() { printf "${M_CSI}?25h"; }

# Disable/enable terminal autowrap. With autowrap off the terminal clips any
# line that overruns the right edge instead of spilling it onto column 0 of the
# next row, where the in-place (\033[H) redraw would never overwrite it.
menu_disable_wrap() { printf "${M_CSI}?7l"; }
menu_enable_wrap() { printf "${M_CSI}?7h"; }

# Gather commit and version info for the menu header
menu_gather_info() {
    # Current Script Commit (local HEAD) and branch
    if [[ -d "${SCRIPT_DIR}/.git" ]] && command -v git &>/dev/null; then
        MENU_SCRIPT_COMMIT=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null | cut -c1-5) || MENU_SCRIPT_COMMIT="N/A"
        MENU_SCRIPT_BRANCH=$(git -C "$SCRIPT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null) || MENU_SCRIPT_BRANCH=""
    else
        MENU_SCRIPT_COMMIT="N/A"
        MENU_SCRIPT_BRANCH=""
    fi

    # Master (remote) Script Commit — detect default branch of origin
    if [[ -d "${SCRIPT_DIR}/.git" ]] && command -v git &>/dev/null; then
        # Resolve origin's default branch (origin/HEAD -> origin/<branch>)
        local remote_default
        remote_default=$(git -C "$SCRIPT_DIR" symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's|refs/remotes/origin/||') || remote_default=""
        if [[ -z "$remote_default" ]]; then
            # Fallback: try to resolve via ls-remote
            remote_default=$(git -C "$SCRIPT_DIR" ls-remote --symref origin HEAD 2>/dev/null | awk '/^ref:/ {sub("refs/heads/",""); print $2; exit}') || remote_default="main"
        fi
        MENU_SCRIPT_MASTER_BRANCH="${remote_default:-main}"
        git -C "$SCRIPT_DIR" fetch origin "$MENU_SCRIPT_MASTER_BRANCH" 2>/dev/null || true
        MENU_SCRIPT_MASTER=$(git -C "$SCRIPT_DIR" rev-parse "origin/${MENU_SCRIPT_MASTER_BRANCH}" 2>/dev/null | cut -c1-5) || MENU_SCRIPT_MASTER="N/A"
        [[ -z "$MENU_SCRIPT_MASTER" ]] && MENU_SCRIPT_MASTER="N/A"
    else
        MENU_SCRIPT_MASTER="N/A"
        MENU_SCRIPT_MASTER_BRANCH="main"
    fi

    # Current XO Commit (installed) and branch
    # Use sudo test because INSTALL_DIR may have o-rwx permissions (security hardening)
    local menu_install_dir="${INSTALL_DIR:-/opt/xen-orchestra}"
    if sudo test -d "${menu_install_dir}/.git" 2>/dev/null; then
        local dir_owner
        dir_owner=$(stat -c '%U' "$menu_install_dir" 2>/dev/null) || dir_owner="root"
        MENU_XO_COMMIT=$(sudo -u "$dir_owner" git -C "$menu_install_dir" rev-parse HEAD 2>/dev/null | cut -c1-5) || MENU_XO_COMMIT="N/A"
        [[ -z "$MENU_XO_COMMIT" ]] && MENU_XO_COMMIT="N/A"
        MENU_XO_BRANCH=$(sudo -u "$dir_owner" git -C "$menu_install_dir" rev-parse --abbrev-ref HEAD 2>/dev/null) || MENU_XO_BRANCH=""
        [[ -z "$MENU_XO_BRANCH" ]] && MENU_XO_BRANCH=""
    else
        MENU_XO_COMMIT="N/A"
        MENU_XO_BRANCH=""
    fi

    # Master XO Commit — detect default branch of vatesfr/xen-orchestra
    local xo_default_branch
    xo_default_branch=$(git ls-remote --symref https://github.com/vatesfr/xen-orchestra HEAD 2>/dev/null | awk '/^ref:/ {sub("refs/heads/",""); print $2; exit}') || xo_default_branch="master"
    MENU_XO_MASTER_BRANCH="${xo_default_branch:-master}"
    MENU_XO_MASTER=$(git ls-remote https://github.com/vatesfr/xen-orchestra "refs/heads/${MENU_XO_MASTER_BRANCH}" 2>/dev/null | cut -f1 | cut -c1-5) || MENU_XO_MASTER="N/A"
    [[ -z "$MENU_XO_MASTER" ]] && MENU_XO_MASTER="N/A"

    # How many commits the installed tree trails master by. Only computed when
    # the installed commit differs from master; the clone is full depth
    # (see install_xen_orchestra), so the count is done locally after fetching
    # the master ref. Stays empty on any failure so the line renders as before.
    MENU_XO_BEHIND=""
    if [[ "$MENU_XO_COMMIT" != "N/A" && "$MENU_XO_MASTER" != "N/A" && "$MENU_XO_COMMIT" != "$MENU_XO_MASTER" ]]; then
        local behind_owner behind_count
        behind_owner=$(stat -c '%U' "$menu_install_dir" 2>/dev/null) || behind_owner="root"
        if sudo -u "$behind_owner" git -C "$menu_install_dir" fetch --quiet origin "$MENU_XO_MASTER_BRANCH" 2>/dev/null; then
            # HEAD..FETCH_HEAD = commits on master that the install doesn't have
            behind_count=$(sudo -u "$behind_owner" git -C "$menu_install_dir" rev-list --count HEAD..FETCH_HEAD 2>/dev/null) || behind_count=""
            if [[ "$behind_count" =~ ^[0-9]+$ ]] && (( behind_count > 0 )); then
                if (( behind_count == 1 )); then
                    MENU_XO_BEHIND="1 commit behind"
                else
                    MENU_XO_BEHIND="${behind_count} commits behind"
                fi
            fi
        fi
    fi

    # Current Node version
    if command -v node &>/dev/null; then
        MENU_NODE_VERSION=$(node -v 2>/dev/null) || MENU_NODE_VERSION="N/A"
    else
        MENU_NODE_VERSION="N/A"
    fi
}

# Work out how the menu should be laid out at the current terminal size.
#
# Widths are measured from the menu data rather than assumed, because the widest
# row ("Rebuild Xen Orchestra (wipe & reinstall maintain settings)" in the right
# column) is far wider than the nominal column width. The layout then steps down
# through progressively more compact forms until one fits.
menu_compute_layout() {
    ML_TERM_W=$(tput cols 2>/dev/null) || ML_TERM_W=80
    ML_TERM_H=$(tput lines 2>/dev/null) || ML_TERM_H=24
    [[ "$ML_TERM_W" =~ ^[0-9]+$ ]] || ML_TERM_W=80
    [[ "$ML_TERM_H" =~ ^[0-9]+$ ]] || ML_TERM_H=24

    # Natural width of each item: "▸ " (2) + "[ ]" (3) + " " (1) + name, plus
    # " " + hint when hints are shown. Tracked per column group, with (w) and
    # without (nh) hints.
    local i w wh
    local left_w=0 right_w=0 center_w=0
    local left_nh=0 right_nh=0 center_nh=0
    for ((i=0; i<MENU_TOTAL; i++)); do
        w=$(( 6 + ${#MENU_NAMES[i]} ))
        wh=$w
        [[ -n "${MENU_HINTS[i]}" ]] && wh=$(( w + 1 + ${#MENU_HINTS[i]} ))
        if (( i < MENU_LEFT_COUNT )); then
            (( wh > left_w )) && left_w=$wh
            (( w > left_nh )) && left_nh=$w
        elif (( i < MENU_LEFT_COUNT + MENU_RIGHT_COUNT )); then
            (( wh > right_w )) && right_w=$wh
            (( w > right_nh )) && right_nh=$w
        else
            (( wh > center_w )) && center_w=$wh
            (( w > center_nh )) && center_nh=$w
        fi
    done
    local single_w=$left_w single_nh=$left_nh
    (( right_w > single_w )) && single_w=$right_w
    (( center_w > single_w )) && single_w=$center_w
    (( right_nh > single_nh )) && single_nh=$right_nh
    (( center_nh > single_nh )) && single_nh=$center_nh

    # Keep a column of breathing room on each side where there is room to spare
    local avail=$(( ML_TERM_W - 2 ))
    (( avail < 20 )) && avail=$ML_TERM_W

    # Width ladder. Two columns are preferred over one even when that costs the
    # hints, because the stacked form is four rows taller and height is the
    # scarcer resource on a default 80x24 terminal.
    local body_w
    if (( left_w + MENU_COL_GAP + right_w <= avail )); then
        ML_TWO_COL=1; ML_HINTS=1
        ML_COL_W=$(( left_w + MENU_COL_GAP ))
        body_w=$(( left_w + MENU_COL_GAP + right_w ))
        (( center_w > body_w )) && body_w=$center_w
    elif (( left_nh + MENU_COL_GAP + right_nh <= avail )); then
        ML_TWO_COL=1; ML_HINTS=0
        ML_COL_W=$(( left_nh + MENU_COL_GAP ))
        body_w=$(( left_nh + MENU_COL_GAP + right_nh ))
        (( center_nh > body_w )) && body_w=$center_nh
    elif (( single_w <= avail )); then
        ML_TWO_COL=0; ML_HINTS=1
        ML_COL_W=$single_w
        body_w=$single_w
    else
        ML_TWO_COL=0; ML_HINTS=0
        ML_COL_W=$single_nh
        body_w=$single_nh
    fi

    # Header info block. The "(Branch: x)" suffixes are the first detail dropped
    # when a line no longer fits; the "N commits behind" suffix is kept because
    # it is the actionable part of the line.
    ML_BRANCHES=1
    local pass info_w=0
    for pass in 1 2; do
        local script_b="" script_mb="" xo_b="" xo_mb=""
        if (( ML_BRANCHES )); then
            [[ -n "$MENU_SCRIPT_BRANCH" ]]        && script_b=" (Branch: ${MENU_SCRIPT_BRANCH})"
            [[ -n "$MENU_SCRIPT_MASTER_BRANCH" ]] && script_mb=" (Branch: ${MENU_SCRIPT_MASTER_BRANCH})"
            [[ -n "$MENU_XO_BRANCH" ]]            && xo_b=" (Branch: ${MENU_XO_BRANCH})"
            [[ -n "$MENU_XO_MASTER_BRANCH" ]]     && xo_mb=" (Branch: ${MENU_XO_MASTER_BRANCH})"
        fi
        [[ -n "$MENU_XO_BEHIND" ]] && xo_mb+=" - ${MENU_XO_BEHIND}"

        ML_INFO_LABELS=(
            "Current Script Commit :"
            "Master Script Commit  :"
            "Current XO Commit     :"
            "Master XO Commit      :"
            "Current Node          :"
        )
        ML_INFO_VALUES=(
            "${MENU_SCRIPT_COMMIT}${script_b}"
            "${MENU_SCRIPT_MASTER}${script_mb}"
            "${MENU_XO_COMMIT}${xo_b}"
            "${MENU_XO_MASTER}${xo_mb}"
            "$MENU_NODE_VERSION"
        )

        # +2 for the "⚠ " that hangs off the Master XO Commit line
        info_w=0
        for ((i=0; i<${#ML_INFO_LABELS[@]}; i++)); do
            w=$(( ${#ML_INFO_LABELS[i]} + 1 + ${#ML_INFO_VALUES[i]} + 2 ))
            (( w > info_w )) && info_w=$w
        done

        (( info_w <= avail )) && break
        (( pass == 1 )) && ML_BRANCHES=0
    done

    ML_CONTENT_W=$body_w
    (( info_w > ML_CONTENT_W )) && ML_CONTENT_W=$info_w
    (( ML_CONTENT_W > avail )) && ML_CONTENT_W=$avail
    # Widen to fit the title box where there is spare room, so the title is not
    # clipped merely because the item rows happen to be narrow
    local title_w=$(( ${#MENU_TITLE} + 2 ))
    (( title_w > ML_CONTENT_W && title_w <= avail )) && ML_CONTENT_W=$title_w
    (( ML_CONTENT_W < 1 )) && ML_CONTENT_W=1

    # Height ladder: shed decoration in order of how little it costs to lose.
    # Row budget = top blank + banner(3) + blank + info(5) + blank + rule +
    # blank + items + blank + rule + blank + selected + blank + legend(2).
    local item_rows=$(( MENU_LEFT_COUNT + MENU_CENTER_COUNT ))
    (( ML_TWO_COL == 0 )) && item_rows=$MENU_TOTAL
    local fixed=$(( 5 + 1 + 1 + item_rows + 1 + 1 ))   # info, 2 rules, items, selected
    local base=$(( fixed + 3 + 2 ))                    # + banner box + legend, no blanks
    ML_BLANKS=2; ML_BANNER=1; ML_LEGEND=1
    local needed=$(( base + 7 ))                       # all seven spacer rows
    if (( needed > ML_TERM_H )); then
        # Give up the outermost spacers first — the ones between sections do
        # more for legibility than the ones at the very top and bottom
        ML_BLANKS=1
        needed=$(( base + 5 ))
    fi
    if (( needed > ML_TERM_H )); then
        ML_BLANKS=0
        needed=$base
    fi
    if (( needed > ML_TERM_H )); then
        ML_BANNER=0
        needed=$(( needed - 2 ))                       # box becomes one plain line
    fi
    if (( needed > ML_TERM_H )); then
        ML_LEGEND=0
        needed=$(( needed - 2 ))
    fi

    # Nothing left to shed. Report the floor instead of drawing a broken screen.
    ML_MIN_W=$(( single_nh + 2 ))
    ML_MIN_H=$(( fixed + 1 ))
    ML_TOO_SMALL=0
    if (( needed > ML_TERM_H || ML_TERM_W < single_nh )); then
        ML_TOO_SMALL=1
    fi
}

# Render one menu item into $MITEM (colorized) given its index and the width it
# must fit in. Returns the visible width in $MITEM_W so callers can pad.
MITEM=""
MITEM_W=0
menu_render_item() {
    local idx=$1 max_w=$2
    local name="${MENU_NAMES[$idx]}"
    local hint=""
    (( ML_HINTS )) && hint="${MENU_HINTS[$idx]}"

    # "▸ " (2) + "[ ]" (3) + " " (1) leaves max_w - 6 for the name and hint
    local text="$name"
    [[ -n "$hint" ]] && text="${name} ${hint}"
    local avail=$(( max_w - 6 ))
    if (( ${#text} > avail )); then
        # Drop the hint before truncating the name — a clipped name is harder to
        # act on than a missing parenthetical
        if [[ -n "$hint" ]] && (( ${#name} <= avail )); then
            hint=""
            text="$name"
        else
            menu_truncate "$name" "$avail"
            name="$MTRUNC"
            hint=""
            text="$name"
        fi
    fi

    local prefix="  "
    [[ $idx -eq $MENU_CURSOR ]] && prefix="${M_BOLD}${M_BLUE}▸ ${M_RESET}"

    local checkbox="[ ]"
    [[ ${MENU_SELECTED[$idx]} -eq 1 ]] && checkbox="${M_GREEN}[✓]${M_RESET}"

    if [[ $idx -eq $MENU_CURSOR ]]; then
        MITEM="${prefix}${checkbox} ${M_BOLD}${name}${M_RESET}"
    else
        MITEM="${prefix}${checkbox} ${name}"
    fi
    [[ -n "$hint" ]] && MITEM="${MITEM} ${M_DIM}${hint}${M_RESET}"

    MITEM_W=$(( 6 + ${#text} ))
}

# Draw the full menu screen
draw_menu() {
    menu_compute_layout

    local eol=$'\033[K'
    local _buf=""

    # Move cursor to home position (overwrite in place, no flicker)
    _buf+=$'\033[H'

    if (( ML_TOO_SMALL )); then
        # Kept short and clipped to the terminal: a wrapped "too small" notice
        # would be its own instance of the problem it is reporting
        menu_truncate "Terminal too small" "$ML_TERM_W"
        _buf+="${M_BOLD}${M_YELLOW}${MTRUNC}${M_RESET}${eol}"$'\n'
        menu_truncate "Need ${ML_MIN_W}x${ML_MIN_H}, have ${ML_TERM_W}x${ML_TERM_H}" "$ML_TERM_W"
        _buf+="${MTRUNC}${eol}"$'\n'
        _buf+=$'\033[J'
        printf '%s' "$_buf"
        return
    fi

    local content_width=$ML_CONTENT_W
    local margin=0
    (( ML_TERM_W > content_width )) && margin=$(( (ML_TERM_W - content_width) / 2 ))
    local pad=""
    (( margin > 0 )) && printf -v pad '%*s' "$margin" ''

    # blank_hi are the outermost spacers, dropped one tier before the rest
    local blank="" blank_hi=""
    (( ML_BLANKS >= 1 )) && blank="${pad}${eol}"$'\n'
    (( ML_BLANKS >= 2 )) && blank_hi="$blank"

    # Banner
    local banner_text="$MENU_TITLE"
    if (( ML_BANNER )); then
        local inner_width=$((content_width - 2))
        local border_fill
        printf -v border_fill '%*s' "$inner_width" ''
        border_fill="${border_fill// /═}"

        menu_truncate "$banner_text" "$inner_width"
        local btext="$MTRUNC"
        local blpad=$(( (inner_width - ${#btext}) / 2 ))
        local brpad=$(( inner_width - ${#btext} - blpad ))
        local blspaces="" brspaces=""
        (( blpad > 0 )) && printf -v blspaces '%*s' "$blpad" ''
        (( brpad > 0 )) && printf -v brspaces '%*s' "$brpad" ''

        _buf+="$blank_hi"
        _buf+="${pad}${M_BOLD}${M_CYAN}╔${border_fill}╗${M_RESET}${eol}"$'\n'
        _buf+="${pad}${M_BOLD}${M_CYAN}║${blspaces}${btext}${brspaces}║${M_RESET}${eol}"$'\n'
        _buf+="${pad}${M_BOLD}${M_CYAN}╚${border_fill}╝${M_RESET}${eol}"$'\n'
    else
        # No room for the box: keep the title as a single centered line
        menu_truncate "$banner_text" "$content_width"
        local btext="$MTRUNC"
        local blpad=$(( (content_width - ${#btext}) / 2 ))
        local blspaces=""
        (( blpad > 0 )) && printf -v blspaces '%*s' "$blpad" ''
        _buf+="${pad}${blspaces}${M_BOLD}${M_CYAN}${btext}${M_RESET}${eol}"$'\n'
    fi
    _buf+="$blank"

    # Commit and version info (centered as a block). Labels and values come from
    # menu_compute_layout, which has already decided whether branch names fit.
    local il info_max_len=0
    for ((il=0; il<${#ML_INFO_LABELS[@]}; il++)); do
        local full_len=$(( ${#ML_INFO_LABELS[il]} + 1 + ${#ML_INFO_VALUES[il]} ))
        (( full_len > info_max_len )) && info_max_len=$full_len
    done
    local info_lpad=$(( (content_width - info_max_len) / 2 ))
    local info_pad=""
    (( info_lpad > 0 )) && printf -v info_pad '%*s' "$info_lpad" ''
    # The warning line carries a leading "⚠ " (2 columns). Hang it in the left
    # margin by starting that line up to 2 columns earlier, so its label — and
    # the colon that follows — stays aligned with the unmarked lines. Whatever
    # cannot be hung there makes the line that much wider, so it comes off the
    # room available to the value.
    local warn_shift=$info_lpad
    (( warn_shift > 2 )) && warn_shift=2
    local info_warn_pad="${info_pad:warn_shift}"
    local warn_extra=$(( 2 - warn_shift ))
    for ((il=0; il<${#ML_INFO_LABELS[@]}; il++)); do
        local info_color="${M_YELLOW}"
        local label_color="${M_BOLD}"
        [[ $il -eq 4 ]] && info_color="${M_GREEN}"

        # Clip the value to whatever is left of the terminal on this line
        local label="${ML_INFO_LABELS[il]}"
        local value_room=$(( ML_TERM_W - margin - info_lpad - ${#label} - 1 ))
        [[ $il -eq 3 ]] && value_room=$(( value_room - warn_extra ))
        menu_truncate "${ML_INFO_VALUES[il]}" "$value_room"
        local value="$MTRUNC"

        # Highlight the entire Master XO Commit line when an update is available
        if [[ $il -eq 3 && "$MENU_XO_COMMIT" != "N/A" && "$MENU_XO_MASTER" != "N/A" && "$MENU_XO_COMMIT" != "$MENU_XO_MASTER" ]]; then
            local xo_style="${M_BOLD}${M_REVERSE}${M_RED}"
            _buf+="${pad}${info_warn_pad}${xo_style}⚠ ${label} ${value}${M_RESET}${eol}"$'\n'
        else
            _buf+="${pad}${info_pad}${label_color}${label}${M_RESET} ${info_color}${value}${M_RESET}${eol}"$'\n'
        fi
    done
    _buf+="$blank"

    # Separator
    local sep_fill
    printf -v sep_fill '%*s' "$content_width" ''
    sep_fill="${sep_fill// /─}"
    _buf+="${pad}${M_DIM}${sep_fill}${M_RESET}${eol}"$'\n'
    _buf+="$blank"

    local idx
    if (( ML_TWO_COL )); then
        # Two equal columns, then the odd item (if any) centered beneath them
        local row col right_w=$(( content_width - ML_COL_W ))
        for ((row=0; row<MENU_LEFT_COUNT; row++)); do
            local line=""
            for ((col=0; col<2; col++)); do
                if (( col == 0 )); then
                    idx=$row
                else
                    idx=$((MENU_LEFT_COUNT + row))
                fi
                (( idx >= MENU_LEFT_COUNT + MENU_RIGHT_COUNT )) && continue

                if (( col == 0 )); then
                    menu_render_item "$idx" "$ML_COL_W"
                    local padding=$(( ML_COL_W - MITEM_W ))
                    (( padding < 1 )) && padding=1
                    local gap_str
                    printf -v gap_str '%*s' "$padding" ''
                    line="${line}${MITEM}${gap_str}"
                else
                    menu_render_item "$idx" "$right_w"
                    line="${line}${MITEM}"
                fi
            done
            _buf+="${pad}${line}${eol}"$'\n'
        done

        local center_start=$((MENU_LEFT_COUNT + MENU_RIGHT_COUNT))
        for ((idx=center_start; idx<MENU_TOTAL; idx++)); do
            menu_render_item "$idx" "$content_width"
            local clpad=$(( (content_width - MITEM_W) / 2 ))
            local cpad=""
            (( clpad > 0 )) && printf -v cpad '%*s' "$clpad" ''
            _buf+="${pad}${cpad}${MITEM}${eol}"$'\n'
        done
    else
        # Single stacked column, left-aligned: centering each row on its own
        # width reads as ragged once the rows differ in length
        for ((idx=0; idx<MENU_TOTAL; idx++)); do
            menu_render_item "$idx" "$content_width"
            _buf+="${pad}${MITEM}${eol}"$'\n'
        done
    fi

    _buf+="$blank"
    _buf+="${pad}${M_DIM}${sep_fill}${M_RESET}${eol}"$'\n'
    _buf+="$blank"

    # Count selections
    local sel_count=0
    local i
    for ((i=0; i<MENU_TOTAL; i++)); do
        [[ ${MENU_SELECTED[$i]} -eq 1 ]] && sel_count=$((sel_count + 1))
    done
    _buf+="${pad}${M_CYAN}Selected: ${M_GREEN}${sel_count}${M_RESET}${eol}"$'\n'

    # Key legend. The long form names every key; the short form keeps the same
    # information in roughly half the width.
    if (( ML_LEGEND )); then
        _buf+="$blank_hi"
        local keys="↑↓←→ Navigate   SPACE Select/Deselect   ENTER Confirm   Q Quit"
        (( ML_TWO_COL == 0 )) && keys="↑↓ Move  SPACE Select  ENTER Go  Q Quit"
        menu_truncate "$keys" "$content_width"
        _buf+="${pad}${M_YELLOW}${MTRUNC}${M_RESET}${eol}"$'\n'
        if (( content_width >= 38 )); then
            _buf+="${pad}${M_DIM}Legend: ${M_GREEN}[✓]${M_RESET}${M_DIM} selected  ${M_RESET}${M_DIM}[ ] not selected${M_RESET}${eol}"$'\n'
        else
            _buf+="${pad}${eol}"$'\n'
        fi
    fi

    # Drop the final newline: emitting one on the bottom row scrolls the screen,
    # which would push the top of the menu out of view whenever the layout
    # happens to fill the terminal exactly. \033[J still clears anything below.
    _buf="${_buf%$'\n'}"

    # Erase any leftover lines from previous render
    _buf+=$'\033[J'
    printf '%s' "$_buf"
}

# Read a single keypress into MENU_KEY.
#
# Sets a global rather than echoing a value: the caller must not run this in a
# command substitution, because bash resets caught traps in a subshell and
# SIGWINCH defaults to "ignore", so a resize would be swallowed entirely.
#
# Even called directly, bash restarts the read syscall across a trapped signal
# and defers the handler until the read returns — so a blocking read would still
# sit on a stale screen until the next keypress. The short timeout below bounds
# that: the read gives up, the pending WINCH trap runs, and the loop sees
# MENU_RESIZED. A read timeout costs no process, so idling here is cheap.
menu_read_key() {
    local key rc
    MENU_KEY=""

    while true; do
        rc=0
        # rc must be captured via || so a non-zero read (timeout, EOF) is not
        # fatal under set -e
        IFS= read -rsn1 -t "$MENU_READ_TIMEOUT" key 2>/dev/null || rc=$?
        (( rc == 0 )) && break

        if (( MENU_RESIZED )); then
            MENU_RESIZED=0
            MENU_KEY="REDRAW"
            return
        fi

        # rc > 128 is the timeout; anything else is EOF, which ends the menu the
        # same way Enter does
        if (( rc <= 128 )); then
            MENU_KEY="ENTER"
            return
        fi
    done

    # Escape sequence (arrow keys, etc.)
    if [[ "$key" == $'\x1b' ]]; then
        local seq
        IFS= read -rsn1 -t 0.5 seq 2>/dev/null || true
        if [[ "$seq" == "[" ]] || [[ "$seq" == "O" ]]; then
            local code
            IFS= read -rsn1 -t 0.5 code 2>/dev/null || true
            case "$code" in
                A) MENU_KEY="UP"; return ;;
                B) MENU_KEY="DOWN"; return ;;
                C) MENU_KEY="RIGHT"; return ;;
                D) MENU_KEY="LEFT"; return ;;
            esac
        fi
        MENU_KEY="ESCAPE"
        return
    fi

    case "$key" in
        ' ') MENU_KEY="SPACE" ;;
        '') MENU_KEY="ENTER" ;;
        q|Q) MENU_KEY="QUIT" ;;
        *) MENU_KEY="OTHER" ;;
    esac
}

# Get the column (0=left, 1=right, 2=center) and row for a cursor index
menu_get_pos() {
    local idx=$1
    if [[ $idx -lt $MENU_LEFT_COUNT ]]; then
        MCOL=0
        MROW=$idx
    elif [[ $idx -lt $((MENU_LEFT_COUNT + MENU_RIGHT_COUNT)) ]]; then
        MCOL=1
        MROW=$((idx - MENU_LEFT_COUNT))
    else
        MCOL=2
        MROW=$((idx - MENU_LEFT_COUNT - MENU_RIGHT_COUNT))
    fi
}

# Convert column/row to cursor index
menu_set_cursor() {
    local col=$1 row=$2
    local target
    if [[ $col -eq 0 ]]; then
        target=$row
    elif [[ $col -eq 1 ]]; then
        target=$((MENU_LEFT_COUNT + row))
    else
        target=$((MENU_LEFT_COUNT + MENU_RIGHT_COUNT + row))
    fi
    # A row that does not exist leaves the cursor where it was rather than
    # moving it off the end of the list in either direction.
    if [[ $target -ge 0 && $target -lt $MENU_TOTAL ]]; then
        MENU_CURSOR=$target
    fi
}

# Rename sample-xo-config.cfg to xo-config.cfg
menu_rename_config() {
    echo ""
    if [[ -f "$CONFIG_FILE" ]]; then
        log_warning "xo-config.cfg already exists!"
        local overwrite
        read -n 1 -rp "$(echo -e "${YELLOW}[WARNING]${NC}") Overwrite with sample? (y/N) " overwrite < /dev/tty
        echo
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            log_info "Skipping rename."
            return 0
        fi
    fi
    if [[ ! -f "$SAMPLE_CONFIG" ]]; then
        log_error "sample-xo-config.cfg not found in ${SCRIPT_DIR}"
        return 1
    fi
    cp "$SAMPLE_CONFIG" "$CONFIG_FILE"
    log_success "Copied sample-xo-config.cfg to xo-config.cfg"
}

# Edit xo-config.cfg using the preferred editor from config
menu_edit_config() {
    echo ""

    # Ensure config exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        if [[ -f "$SAMPLE_CONFIG" ]]; then
            log_info "xo-config.cfg not found. Creating from sample..."
            cp "$SAMPLE_CONFIG" "$CONFIG_FILE"
            log_success "Created xo-config.cfg from sample."
        else
            log_error "Neither xo-config.cfg nor sample-xo-config.cfg found!"
            return 1
        fi
    fi

    # Read preferred editor from config
    local editor="${PREFERRED_EDITOR:-nano}"

    # Source config to get PREFERRED_EDITOR if not already loaded
    if [[ -f "$CONFIG_FILE" ]]; then
        local cfg_editor
        cfg_editor=$(grep -E '^PREFERRED_EDITOR=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2) || true
        [[ -n "$cfg_editor" ]] && editor="$cfg_editor"
    fi

    # Validate editor choice
    if [[ "$editor" != "nano" ]] && [[ "$editor" != "vim" ]]; then
        log_warning "PREFERRED_EDITOR must be 'nano' or 'vim'. Got: $editor"
        log_info "Falling back to nano."
        editor="nano"
    fi

    # Check if editor is installed
    if ! command -v "$editor" &>/dev/null; then
        log_warning "${editor} is not installed."
        local install_editor
        read -n 1 -rp "$(echo -e "${YELLOW}[WARNING]${NC}") Install ${editor}? (y/N) " install_editor < /dev/tty
        echo
        if [[ "$install_editor" =~ ^[Yy]$ ]]; then
            # Detect package manager if not already done
            if [[ -z "${PKG_INSTALL:-}" ]]; then
                if command -v apt-get &>/dev/null; then
                    PKG_INSTALL="sudo apt-get install -y"
                elif command -v dnf &>/dev/null; then
                    PKG_INSTALL="sudo dnf install -y"
                elif command -v yum &>/dev/null; then
                    PKG_INSTALL="sudo yum install -y"
                else
                    log_error "No supported package manager found."
                    return 1
                fi
            fi
            log_info "Installing ${editor}..."
            # shellcheck disable=SC2086
            run_cmd $PKG_INSTALL "$editor"
            if ! command -v "$editor" &>/dev/null; then
                log_error "Failed to install ${editor}."
                return 1
            fi
            log_success "${editor} installed."
        else
            log_error "Cannot edit without an editor. Please install ${editor} manually."
            return 1
        fi
    fi

    log_info "Opening ${CONFIG_FILE} with ${editor}..."
    "$editor" "$CONFIG_FILE" < /dev/tty
    log_success "Configuration editing complete."
}

# Process selected menu items after user confirms
process_menu_selections() {
    local has_selection=false
    for ((i=0; i<MENU_TOTAL; i++)); do
        [[ ${MENU_SELECTED[$i]} -eq 1 ]] && has_selection=true
    done

    if [[ "$has_selection" == "false" ]]; then
        echo "No items selected."
        return 0
    fi

    # Preparatory operations first (rename, then edit)
    local config_changed=false
    if [[ ${MENU_SELECTED[2]} -eq 1 ]]; then
        menu_rename_config && config_changed=true
    fi

    if [[ ${MENU_SELECTED[8]} -eq 1 ]]; then
        menu_edit_config && config_changed=true
    fi

    # If the config file was renamed or edited, offer to reload the script so
    # the new settings take effect. Reloading re-runs load_config from scratch.
    if [[ "$config_changed" == "true" ]]; then
        echo ""
        if prompt_yes_no "Configuration changed. Do you want to reload the script?"; then
            log_info "Reloading script..."
            release_lock
            exec bash "$SCRIPT_PATH" "${ORIGINAL_ARGS[@]}"
        else
            log_info "Exiting without reload."
            exit 0
        fi
    fi

    # Install Xen Orchestra (full installation with all checks)
    if [[ ${MENU_SELECTED[0]} -eq 1 ]]; then
        install_xo
    fi

    # Update Xen Orchestra
    if [[ ${MENU_SELECTED[1]} -eq 1 ]]; then
        check_required_commands
        check_not_root
        check_sudo
        check_systemctl
        load_config
        detect_package_manager
        check_git
        update_xo
    fi

    # Reconfigure Xen Orchestra
    if [[ ${MENU_SELECTED[6]} -eq 1 ]]; then
        check_required_commands
        check_not_root
        check_sudo
        check_systemctl
        load_config
        reconfigure_xo
    fi

    # Rebuild Xen Orchestra
    if [[ ${MENU_SELECTED[7]} -eq 1 ]]; then
        check_required_commands
        check_not_root
        check_sudo
        check_systemctl
        load_config
        detect_package_manager
        check_git
        rebuild_xo
    fi

    # Install XO Proxy
    if [[ ${MENU_SELECTED[3]} -eq 1 ]]; then
        check_required_commands
        check_not_root
        check_sudo
        detect_package_manager
        load_config
        install_xo_proxy
    fi

    # Restore Backup
    if [[ ${MENU_SELECTED[9]} -eq 1 ]]; then
        check_required_commands
        check_not_root
        check_sudo
        check_systemctl
        load_config
        restore_xo
    fi

    # Deploy Xen Orchestra to a new VM
    # No check_sudo: nothing is installed on this machine unless an ISO writer
    # is missing, and deploy_check_local_deps asks for sudo then.
    if [[ ${MENU_SELECTED[4]} -eq 1 ]]; then
        check_required_commands
        check_not_root
        deploy_xo_vm
    fi

    # Adjust Xen Orchestra Memory Allocation
    if [[ ${MENU_SELECTED[10]} -eq 1 ]]; then
        check_required_commands
        check_not_root
        check_sudo
        check_systemctl
        adjust_xo_memory
    fi

    # VM Template Library
    # Same minimal preflight as --deploy: this targets the pool, reads nothing
    # from the local install and changes nothing on this machine. sudo is asked
    # for by deploy_check_local_deps only if an ISO writer has to be installed.
    if [[ ${MENU_SELECTED[5]} -eq 1 ]]; then
        check_required_commands
        check_not_root
        build_vm_templates
    fi
}

# Run the interactive menu
run_menu() {
    # Load config silently for header info (don't error if missing)
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE" 2>/dev/null || true
    elif [[ -f "$SAMPLE_CONFIG" ]]; then
        source "$SAMPLE_CONFIG" 2>/dev/null || true
    fi
    INSTALL_DIR=${INSTALL_DIR:-/opt/xen-orchestra}
    PREFERRED_EDITOR=${PREFERRED_EDITOR:-nano}

    # Reset selection state. Sized from MENU_TOTAL rather than written out:
    # a literal list silently drifts when a menu item is added, and every
    # index past its end is an unbound-variable crash under `set -u`.
    MENU_CURSOR=0
    MENU_SELECTED=()
    local i
    for ((i = 0; i < MENU_TOTAL; i++)); do
        MENU_SELECTED[i]=0
    done

    # Gather version/commit info for header display
    menu_gather_info

    # Save terminal state (global so cleanup_menu trap can access it)
    saved_stty=$(stty -g 2>/dev/null) || saved_stty=""
    menu_hide_cursor
    menu_disable_wrap
    stty -echo 2>/dev/null || true

    # Restore terminal on exit
    cleanup_menu() {
        menu_show_cursor
        menu_enable_wrap
        [[ -n "$saved_stty" ]] && stty "$saved_stty" 2>/dev/null || stty echo 2>/dev/null
    }
    trap cleanup_menu EXIT
    # Only raise a flag here — drawing from inside the handler could interleave
    # with a draw already in progress. menu_read_key turns this into a REDRAW.
    trap 'MENU_RESIZED=1' WINCH

    clear
    draw_menu

    while true; do
        local key
        # Direct call, not $(...) — see menu_read_key for why the subshell
        # would break live resize handling.
        menu_read_key
        key="$MENU_KEY"

        case "$key" in
            UP)
                # Single-column layout has no grid to navigate — walk the list
                if (( ML_TWO_COL == 0 )); then
                    if (( MENU_CURSOR == 0 )); then
                        MENU_CURSOR=$((MENU_TOTAL - 1))
                    else
                        MENU_CURSOR=$((MENU_CURSOR - 1))
                    fi
                    draw_menu
                    continue
                fi
                menu_get_pos $MENU_CURSOR
                if [[ $MCOL -eq 2 ]]; then
                    # From the centered row, go up into the last row of the left column
                    menu_set_cursor 0 $((MENU_LEFT_COUNT - 1))
                else
                    local col_size
                    if [[ $MCOL -eq 0 ]]; then
                        col_size=$MENU_LEFT_COUNT
                    else
                        col_size=$MENU_RIGHT_COUNT
                    fi
                    if [[ $MROW -eq 0 ]]; then
                        # Wrap from the top of a column down to the centered
                        # row, or to the column's own bottom when the item
                        # count is even and there is no centered row
                        if (( MENU_CENTER_COUNT > 0 )); then
                            menu_set_cursor 2 0
                        else
                            menu_set_cursor $MCOL $((col_size - 1))
                        fi
                    else
                        menu_set_cursor $MCOL $((MROW - 1))
                    fi
                fi
                ;;
            DOWN)
                if (( ML_TWO_COL == 0 )); then
                    MENU_CURSOR=$(( (MENU_CURSOR + 1) % MENU_TOTAL ))
                    draw_menu
                    continue
                fi
                menu_get_pos $MENU_CURSOR
                if [[ $MCOL -eq 2 ]]; then
                    # From the centered row, wrap to the top of the left column
                    menu_set_cursor 0 0
                else
                    local col_size
                    if [[ $MCOL -eq 0 ]]; then
                        col_size=$MENU_LEFT_COUNT
                    else
                        col_size=$MENU_RIGHT_COUNT
                    fi
                    if [[ $MROW -ge $((col_size - 1)) ]]; then
                        # Wrap from the bottom of a column down to the centered
                        # row, or back to the column's own top when there is
                        # no centered row
                        if (( MENU_CENTER_COUNT > 0 )); then
                            menu_set_cursor 2 0
                        else
                            menu_set_cursor $MCOL 0
                        fi
                    else
                        menu_set_cursor $MCOL $((MROW + 1))
                    fi
                fi
                ;;
            LEFT)
                # No second column to move to in the stacked layout
                (( ML_TWO_COL == 0 )) && continue
                menu_get_pos $MENU_CURSOR
                if [[ $MCOL -eq 1 ]]; then
                    local target_row=$MROW
                    [[ $target_row -ge $MENU_LEFT_COUNT ]] && target_row=$((MENU_LEFT_COUNT - 1))
                    menu_set_cursor 0 $target_row
                fi
                ;;
            RIGHT)
                (( ML_TWO_COL == 0 )) && continue
                menu_get_pos $MENU_CURSOR
                if [[ $MCOL -eq 0 ]]; then
                    local target_row=$MROW
                    [[ $target_row -ge $MENU_RIGHT_COUNT ]] && target_row=$((MENU_RIGHT_COUNT - 1))
                    menu_set_cursor 1 $target_row
                fi
                ;;
            SPACE)
                if [[ ${MENU_SELECTED[$MENU_CURSOR]} -eq 1 ]]; then
                    MENU_SELECTED[$MENU_CURSOR]=0
                else
                    MENU_SELECTED[$MENU_CURSOR]=1
                fi
                ;;
            ENTER)
                break
                ;;
            REDRAW)
                # Terminal resized. The draw_menu at the foot of the loop
                # recomputes the layout, so there is nothing to do here.
                ;;
            QUIT)
                cleanup_menu
                trap - EXIT
                trap - WINCH
                clear
                echo "Cancelled."
                exit 0
                ;;
        esac

        draw_menu
    done

    # Restore terminal before running operations
    cleanup_menu
    trap - EXIT
    trap - WINCH
    clear

    # Restore the original ERR trap
    trap 'log_error "Script failed at line $LINENO: $BASH_COMMAND. If the service was stopped, run: sudo systemctl start xo-server"' ERR

    # Execute selected operations
    process_menu_selections
}

# Main entry point
main() {
    # Pre-parse global flags before dispatching to operations.
    # This allows flags like --non-interactive and --dry-run to appear in any order.
    local OPERATION=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --non-interactive|--yes)
                NON_INTERACTIVE=true
                ;;
            --dry-run|--check)
                DRY_RUN=true
                ;;
            --backup-file)
                shift
                RESTORE_BACKUP_FILE="${1:-}"
                ;;
            --log-file)
                shift
                LOG_FILE="${1:-}"
                ;;
            --json-logs)
                JSON_LOGS=true
                ;;
            --allow-eol-distro)
                ALLOW_EOL_DISTRO=true
                ;;
            --version)
                # Informational: print revision and exit before self-update/lock.
                show_version
                exit 0
                ;;
            --install|--update|--restore|--rebuild|--reconfigure|--proxy|--deploy|--build-templates|--adjust-memory|--flush-tokens|--uninstall|--help)
                OPERATION="$1"
                ;;
            *)
                log_error "Unknown option: $1"
                log_error "Run with --help for usage information."
                exit 1
                ;;
        esac
        shift
    done

    # Validate --json-logs requires --log-file
    if [[ "$JSON_LOGS" == "true" ]] && [[ -z "$LOG_FILE" ]]; then
        log_error "--json-logs requires --log-file PATH"
        exit 1
    fi

    # Self-update before doing anything (skip for --help to avoid delays)
    if [[ "$OPERATION" != "--help" ]]; then
        self_update_script
    fi

    if [[ "$NON_INTERACTIVE" == "true" ]] && [[ -z "$OPERATION" ]]; then
        log_error "--non-interactive requires an explicit operation flag (--install, --update, --restore, --rebuild, --reconfigure, --proxy, --deploy, --adjust-memory, --flush-tokens, --uninstall)"
        exit 1
    fi

    # --deploy is a guided, prompt-driven operation: there is no config file to
    # read the pool master address, credentials, or guest network out of, so
    # there is nothing sensible to fall back to without a terminal.
    if [[ "$NON_INTERACTIVE" == "true" ]] && [[ "$OPERATION" == "--deploy" ]]; then
        log_error "--deploy cannot be combined with --non-interactive."
        log_error "It needs connection details that only exist as answers to its prompts."
        exit 1
    fi

    # Acquire exclusive lock for all mutating operations (not --help).
    # --deploy is excluded: it changes nothing on this machine, and holding the
    # install lock for the length of a remote deploy would block unrelated
    # local operations for no reason.
    if [[ "$OPERATION" != "--help" ]] && [[ "$OPERATION" != "--deploy" ]]; then
        acquire_lock
    fi

    case "$OPERATION" in
        --update)
            check_required_commands
            check_not_root
            check_sudo
            check_systemctl
            load_config
            detect_package_manager
            check_git
            update_xo
            ;;
        --restore)
            check_required_commands
            check_not_root
            check_sudo
            check_systemctl
            load_config
            restore_xo
            ;;
        --rebuild)
            check_required_commands
            check_not_root
            check_sudo
            check_systemctl
            load_config
            detect_package_manager
            check_git
            rebuild_xo
            ;;
        --reconfigure)
            check_required_commands
            check_not_root
            check_sudo
            check_systemctl
            load_config
            reconfigure_xo
            ;;
        --proxy)
            check_required_commands
            check_not_root
            check_sudo
            detect_package_manager
            load_config
            install_xo_proxy
            ;;
        --deploy)
            # Deliberately minimal: this operation targets a VM that does not
            # exist yet, reads nothing from the local install, and changes
            # nothing on this machine. No check_systemctl, no load_config, and
            # no check_sudo — deploy_check_local_deps asks for sudo only if an
            # ISO writer actually has to be installed.
            check_required_commands
            check_not_root
            deploy_xo_vm
            ;;
        --build-templates)
            # Same reasoning as --deploy: targets the pool, not this machine.
            check_required_commands
            check_not_root
            build_vm_templates
            ;;
        --adjust-memory)
            check_required_commands
            check_not_root
            check_sudo
            check_systemctl
            adjust_xo_memory
            ;;
        --flush-tokens)
            check_required_commands
            check_not_root
            check_sudo
            flush_tokens_standalone
            ;;
        --install)
            install_xo
            ;;
        --uninstall)
            cleanup_xo
            ;;
        --help)
            show_help
            ;;
        *)
            run_menu
            ;;
    esac
}

# Allow test harnesses to source the script without executing main()
if [[ "${_XO_SOURCE_ONLY:-0}" != "1" ]]; then
    main "$@"
fi
