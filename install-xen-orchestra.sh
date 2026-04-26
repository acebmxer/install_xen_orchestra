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
# Based on: https://docs.xen-orchestra.com/installation#from-the-sources
#
# This script installs Xen Orchestra from source with:
# - Node.js 20 LTS
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
LATEST_CONFIG_VERSION=1

# Runtime mode flags (set via CLI flags in main())
NON_INTERACTIVE=false
RESTORE_BACKUP_FILE=""
DRY_RUN=false

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
    GIT_BRANCH=${GIT_BRANCH:-master}
    BACKUP_DIR=${BACKUP_DIR:-/opt/xo-backups}
    BACKUP_KEEP=${BACKUP_KEEP:-5}
    NODE_VERSION=${NODE_VERSION:-24.15.0}
    SERVICE_USER=${SERVICE_USER:-root}
    DEBUG_MODE=${DEBUG_MODE:-false}
    BIND_ADDRESS=${BIND_ADDRESS:-0.0.0.0}
    REDIRECT_TO_HTTPS=${REDIRECT_TO_HTTPS:-false}
    REVERSE_PROXY_TRUST=${REVERSE_PROXY_TRUST:-false}
    REDIS_URI=${REDIS_URI:-}
    REDIS_SOCKET=${REDIS_SOCKET:-}
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
        echo "" >> "$cfg_file"
        echo "# Config schema version — do not modify manually" >> "$cfg_file"
        echo "CONFIG_VERSION=1" >> "$cfg_file"
        CONFIG_VERSION=1
    fi

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

# Detect OS distribution
detect_os() {
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

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."

    detect_os
    # shellcheck disable=SC2086
    run_cmd $PKG_UPDATE

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
                run_cmd sudo dnf install -y epel-release || true
                run_cmd sudo dnf config-manager --enable devel || true
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
        local XO_UID=$(id -u "$SERVICE_USER" 2>/dev/null || echo "unknown")
        local XO_GID=$(id -g "$SERVICE_USER" 2>/dev/null || echo "unknown")
        log_info "Service user UID:GID is ${XO_UID}:${XO_GID}"
    fi
}

# Start and enable Redis
setup_redis() {
    log_info "Setting up Redis..."

    check_systemctl

    # Try redis-server first, then valkey
    if systemctl list-unit-files 2>/dev/null | grep -q redis; then
        run_cmd sudo systemctl enable redis-server 2>/dev/null || run_cmd sudo systemctl enable redis 2>/dev/null || true
        run_cmd sudo systemctl start redis-server 2>/dev/null || run_cmd sudo systemctl start redis 2>/dev/null || true
    elif systemctl list-unit-files 2>/dev/null | grep -q valkey; then
        run_cmd sudo systemctl enable valkey 2>/dev/null || true
        run_cmd sudo systemctl start valkey 2>/dev/null || true
    else
        log_warning "Neither redis nor valkey service found in systemd units"
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        echo "[DRY-RUN] Would verify Redis is running"
        return 0
    fi

    # Verify Redis is running
    if command -v redis-cli >/dev/null 2>&1 && redis-cli ping 2>/dev/null | grep -q PONG; then
        log_success "Redis is running"
    else
        log_error "Redis is not running or not responding"
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
    local CURRENT_SWAP=$(free -m | awk '/^Swap:/ {print $2}')
    
    if [[ $CURRENT_SWAP -ge $MIN_SWAP_MB ]]; then
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

# Usage: build_xo [clean]
# If "clean" is passed, turbo cache will be cleared first
build_xo() {
    local CLEAN_BUILD="${1:-}"
    
    log_info "Building Xen Orchestra (this may take a while)..."

    # Ensure swap space exists to prevent OOM
    ensure_swap_space

    # Clear turbo cache if clean build requested
    if [[ "$CLEAN_BUILD" == "clean" ]]; then
        log_info "Clearing build cache for clean rebuild..."
        if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
            run_cmd sudo -u "$SERVICE_USER" rm -rf "$INSTALL_DIR/node_modules/.cache/turbo" 2>/dev/null || true
            run_cmd sudo -u "$SERVICE_USER" rm -rf "$INSTALL_DIR/.turbo" 2>/dev/null || true
        else
            run_cmd sudo rm -rf "$INSTALL_DIR/node_modules/.cache/turbo" 2>/dev/null || true
            run_cmd sudo rm -rf "$INSTALL_DIR/.turbo" 2>/dev/null || true
        fi
    fi

    # Calculate available memory (RAM + swap) and set build limits to prevent OOM
    local TOTAL_RAM_MB=$(free -m | awk '/^Mem:/ {print $2}')
    local TOTAL_SWAP_MB=$(free -m | awk '/^Swap:/ {print $2}')
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
    local TURBO_CACHE="remote:r"
    local CONCURRENCY_FLAG=""
    if [[ -n "$TURBO_CONCURRENCY" ]]; then
        CONCURRENCY_FLAG="--concurrency=$TURBO_CONCURRENCY"
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
        run_cmd sudo -u "$SERVICE_USER" bash -c "cd '$INSTALL_DIR' && NODE_OPTIONS='$NODE_OPTIONS' TURBO_CACHE='$TURBO_CACHE' yarn && NODE_OPTIONS='$NODE_OPTIONS' TURBO_CACHE='$TURBO_CACHE' yarn build $CONCURRENCY_FLAG"
    else
        run_cmd sudo bash -c "cd '$INSTALL_DIR' && NODE_OPTIONS='$NODE_OPTIONS' TURBO_CACHE='$TURBO_CACHE' yarn && NODE_OPTIONS='$NODE_OPTIONS' TURBO_CACHE='$TURBO_CACHE' yarn build $CONCURRENCY_FLAG"
    fi

    log_success "Xen Orchestra built successfully"
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

    run_cmd sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
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

    log_success "SSL certificates generated in $SSL_CERT_DIR"
}

# Configure Xen Orchestra
configure_xo() {
    log_info "Configuring Xen Orchestra..."

    local XO_CONFIG_FILE="/etc/xo-server/config.toml"

    # Create config directory
    run_cmd sudo mkdir -p /etc/xo-server

    # Create mounts directory with proper permissions
    # Note: /run/xo-server is tmpfs and will be recreated by systemd on boot
    run_cmd sudo mkdir -p /run/xo-server/mounts
    run_cmd sudo chmod 755 /run/xo-server/mounts
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        run_cmd sudo chown -R "$SERVICE_USER:$SERVICE_USER" /run/xo-server
        run_cmd sudo chmod 755 /run/xo-server/mounts
    fi

    # Create configuration file
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Would write $XO_CONFIG_FILE"
    else
    sudo tee "$XO_CONFIG_FILE" > /dev/null << EOF
# Xen Orchestra Server Configuration
# Generated by install script

$(if [[ "$REDIRECT_TO_HTTPS" == "true" ]]; then
echo "# Redirect all HTTP to HTTPS"
echo "[http]"
echo "redirectToHttps = true"
echo ""
fi)$(if [[ "$REVERSE_PROXY_TRUST" != "false" ]]; then
echo "# Trust X-Forwarded-* headers from reverse proxy"
echo "[http]"
if [[ "$REVERSE_PROXY_TRUST" == "true" ]]; then
  echo "useForwardedHeaders = true"
else
  echo "# Trust only specific proxy IP addresses"
  echo "useForwardedHeaders = ["
  for ip in $REVERSE_PROXY_TRUST; do
    echo "  '$ip',"
  done
  echo "]"
fi
echo ""
fi)# HTTP settings
[[http.listen]]
hostname = '${BIND_ADDRESS}'
port = ${HTTP_PORT}

# HTTPS settings
[[http.listen]]
hostname = '${BIND_ADDRESS}'
port = ${HTTPS_PORT}
cert = "${SSL_CERT_DIR}/${SSL_CERT_FILE}"
key = "${SSL_CERT_DIR}/${SSL_KEY_FILE}"

$(if [[ -n "$REDIS_URI" ]]; then
echo "# Redis connection"
echo "[redis]"
echo "uri = '$REDIS_URI'"
echo ""
elif [[ -n "$REDIS_SOCKET" ]]; then
echo "# Redis connection via Unix socket"
echo "[redis]"
echo "socket = '$REDIS_SOCKET'"
echo ""
fi)[remoteOptions]
mountsDir = '/run/xo-server/mounts'
useSudo = true
nfsOptions = 'vers=4.1,rw,nolock,sec=sys'
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

    local NODE_PATH=$(command -v node)
    local EXEC_USER="${SERVICE_USER:-root}"
    local XO_SERVER_PATH="${INSTALL_DIR}/packages/xo-server/dist/cli.mjs"
    local DEBUG_ENV=""

    if [[ "$DEBUG_MODE" == "true" ]]; then
        DEBUG_ENV="DEBUG=xo:main"
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Would write /etc/systemd/system/xo-server.service"
    else
    sudo tee /etc/systemd/system/xo-server.service > /dev/null << EOF
[Unit]
Description=Xen Orchestra Server
After=network-online.target redis.service
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

# Allow binding to privileged ports (80/443)
AmbientCapabilities=CAP_NET_BIND_SERVICE
# Bounding set: ceiling for all processes in this service tree.
# CAP_NET_BIND_SERVICE: bind to ports 80/443
# CAP_SETUID/CAP_SETGID/CAP_AUDIT_WRITE: required for sudo to function
# CAP_SYS_ADMIN: required for mount syscall (NFS/CIFS remotes)
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SYS_ADMIN CAP_AUDIT_WRITE

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
# Per official docs: https://docs.xen-orchestra.com/installation#from-the-sources
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
# Ref: https://docs.xen-orchestra.com/installation#from-the-sources
${SERVICE_USER} ALL=(root) NOPASSWD: /bin/mount, /usr/bin/mount, /bin/umount, /usr/bin/umount, /bin/findmnt, /usr/bin/findmnt
EOF
        fi # end DRY_RUN check

        run_cmd sudo chmod 440 "$SUDOERS_FILE"

        log_success "Sudo configured for ${SERVICE_USER} (mount, umount, findmnt)"
    fi
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

    # Create backup (excluding node_modules to save space)
    run_cmd sudo cp -r "$INSTALL_DIR" "$BACKUP_PATH"
    run_cmd sudo rm -rf "${BACKUP_PATH}/node_modules"

    log_success "Backup created: $BACKUP_PATH"

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

    # Parse task count — jq preferred, node.js fallback (guaranteed on any XO install)
    if command -v jq &>/dev/null; then
        task_count=$(printf '%s' "$task_response" \
            | jq '[.[] | select((.properties.name // "") != "XO user authentication")] | length' \
            2>/dev/null) || task_count=0
    else
        task_count=$(printf '%s' "$task_response" | node -e '
            let d = "";
            process.stdin.on("data", c => d += c);
            process.stdin.on("end", () => {
                try {
                    const a = JSON.parse(d);
                    const filtered = Array.isArray(a)
                        ? a.filter(t => (t.properties && t.properties.name) !== "XO user authentication")
                        : [];
                    process.stdout.write(String(filtered.length));
                } catch (e) { process.stdout.write("0"); }
            });
        ' 2>/dev/null) || task_count=0
    fi

    # Ensure task_count is a valid integer before numeric comparison
    if ! [[ "$task_count" =~ ^[0-9]+$ ]]; then
        task_count=0
    fi

    if [[ "$task_count" -gt 0 ]]; then
        log_error "Update aborted: ${task_count} active task(s) found in Xen Orchestra."
        log_error "Task check performed by: ${auth_label}"
        log_error "Active tasks:"

        # List task names — node fallback if jq not available
        if command -v jq &>/dev/null; then
            while IFS= read -r task_line; do
                printf '%b\n' "${RED}[ERROR]${NC}   - ${task_line}"
            done < <(printf '%s' "$task_response" \
                | jq -r '[.[] | select((.properties.name // "") != "XO user authentication")] | .[] | (.properties.name // .id // "unknown task")' \
                2>/dev/null || true)
        else
            printf '%s' "$task_response" | node -e '
                let d = "";
                process.stdin.on("data", c => d += c);
                process.stdin.on("end", () => {
                    try {
                        const tasks = JSON.parse(d);
                        if (Array.isArray(tasks)) {
                            tasks
                                .filter(t => (t.properties && t.properties.name) !== "XO user authentication")
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

    local INSTALLED_COMMIT=$(get_installed_commit)
    local REMOTE_COMMIT=$(get_remote_commit)

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

    # Rebuild with clean cache to ensure fresh build
    build_xo clean

    # Regenerate the systemd service file to pick up any script changes
    create_systemd_service

    # Regenerate sudoers for non-root service user (tightens legacy rules)
    configure_sudo

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

    # Ensure Node.js version matches config (upgrade/downgrade if needed)
    install_nodejs
    install_yarn

    # Clean build to ensure no stale artefacts
    build_xo clean

    # Regenerate the systemd service file to pick up any script changes
    create_systemd_service

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
    run_cmd sudo systemctl stop xo-server || true

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

    # Regenerate configuration
    configure_xo

    # Regenerate systemd service
    create_systemd_service

    # Update sudoers for non-root service user
    configure_sudo

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
    log_info "Access Xen Orchestra at:"
    echo "  - http://$(hostname):${HTTP_PORT}"
    echo "  - https://$(hostname):${HTTPS_PORT}"
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
    SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || \
                ip route get 1 2>/dev/null | awk '{print $7;exit}' || \
                hostname)
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
    echo "Service Management:"
    echo "  - Start:   sudo systemctl start xo-server"
    echo "  - Stop:    sudo systemctl stop xo-server"
    echo "  - Status:  sudo systemctl status xo-server"
    echo "  - Logs:    sudo journalctl -u xo-server -f"
    echo ""
    echo "To update Xen Orchestra, run:"
    echo "  $0 --update"
    echo ""
    log_warning "Please change the default password immediately!"
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
        # shellcheck disable=SC2086
        run_cmd $PKG_UPDATE
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
    log_info "Testing SSH connection to $HOST_USERNAME@$POOL_MASTER_IP..."
    if ! sshpass -p "$HOST_PASSWORD" ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$HOST_USERNAME@$POOL_MASTER_IP" "echo 'Connection successful'" &>/dev/null; then
        # Try installing sshpass if not available
        if ! command -v sshpass &> /dev/null; then
            log_info "Installing sshpass..."
            # shellcheck disable=SC2086
            run_cmd $PKG_INSTALL sshpass
            # Retry connection
            if ! sshpass -p "$HOST_PASSWORD" ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$HOST_USERNAME@$POOL_MASTER_IP" "echo 'Connection successful'" &>/dev/null; then
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
        if sshpass -p "$HOST_PASSWORD" ssh -o StrictHostKeyChecking=accept-new "$HOST_USERNAME@$POOL_MASTER_IP" 'bash -s' << 'REMOTE_LICENSE_PATCH'
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

# Show help
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
    echo "  --uninstall            Remove XO service, install dir, certs, and sudoers (guided)"
    echo "  --help                 Show this help message"
    echo ""
    echo "Automation Flags (can be combined with any operation):"
    echo "  --non-interactive      Bypass all interactive prompts; use config defaults"
    echo "  --yes                  Alias for --non-interactive"
    echo "  --backup-file NAME     With --restore: select specific backup by directory name"
    echo "  --dry-run, --check     Show what would be done without making any changes"
    echo "  --log-file PATH        Append log output to PATH (plain-text by default)"
    echo "  --json-logs            Write structured JSON lines to --log-file instead of plain text"
    echo ""
    echo "Environment Variables:"
    echo "  XO_DEBUG=1              Enable debug mode (prints all commands with 'set -x')"
    echo "  XO_NO_SELF_UPDATE=1     Skip automatic script self-update check"
    echo ""
    echo "Configuration:"
    echo "  Copy sample-xo-config.cfg to xo-config.cfg and edit as needed."
    echo "  If xo-config.cfg is not found, it will be created automatically."
    echo "  To switch branches, edit GIT_BRANCH in xo-config.cfg and run --update."
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
M_MAGENTA="${M_CSI}35m"
M_CYAN="${M_CSI}36m"
M_BLINK="${M_CSI}5m"
M_REVERSE="${M_CSI}7m"

# Menu item names (left column indices 0-3, right column indices 4-7)
MENU_NAMES=(
    "Install Xen Orchestra"
    "Update Xen Orchestra"
    "Rename Sample-xo-config.cfg"
    "Install XO Proxy"
    "Reconfigure Xen Orchestra"
    "Rebuild Xen Orchestra"
    "Edit xo-config.cfg"
    "Restore Backup"
)
MENU_HINTS=(
    ""
    ""
    ""
    ""
    "(made changes to config)"
    "(wipe & reinstall maintain settings)"
    ""
    ""
)

MENU_LEFT_COUNT=4
MENU_RIGHT_COUNT=4
MENU_TOTAL=8
MENU_CURSOR=0
MENU_SELECTED=(0 0 0 0 0 0 0 0)
MCOL=0
MROW=0
MENU_SCRIPT_COMMIT="N/A"
MENU_SCRIPT_MASTER="N/A"
MENU_XO_COMMIT="N/A"
MENU_XO_MASTER="N/A"
MENU_NODE_VERSION="N/A"

# Hide/show cursor
menu_hide_cursor() { printf "${M_CSI}?25l"; }
menu_show_cursor() { printf "${M_CSI}?25h"; }

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

    # Current Node version
    if command -v node &>/dev/null; then
        MENU_NODE_VERSION=$(node -v 2>/dev/null) || MENU_NODE_VERSION="N/A"
    else
        MENU_NODE_VERSION="N/A"
    fi
}

# Draw the full menu screen
draw_menu() {
    local term_width
    term_width=$(tput cols 2>/dev/null) || term_width=80
    local col_width=42
    local content_width=$((col_width * 2))
    local margin=0
    (( term_width > content_width )) && margin=$(( (term_width - content_width) / 2 ))
    local pad=""
    (( margin > 0 )) && printf -v pad '%*s' "$margin" ''
    local eol=$'\033[K'
    local _buf=""

    # Move cursor to home position (overwrite in place, no flicker)
    _buf+=$'\033[H'

    # Banner box
    local inner_width=$((content_width - 2))
    local border_fill
    printf -v border_fill '%*s' "$inner_width" ''
    border_fill="${border_fill// /═}"

    local banner_text="Install Xen Orchestra from Sources Setup and Update"
    local banner_len=${#banner_text}
    local blpad=$(( (inner_width - banner_len) / 2 ))
    local brpad=$(( inner_width - banner_len - blpad ))
    local blspaces="" brspaces=""
    (( blpad > 0 )) && printf -v blspaces '%*s' "$blpad" ''
    (( brpad > 0 )) && printf -v brspaces '%*s' "$brpad" ''

    _buf+="${pad}${eol}"$'\n'
    _buf+="${pad}${M_BOLD}${M_CYAN}╔${border_fill}╗${M_RESET}${eol}"$'\n'
    _buf+="${pad}${M_BOLD}${M_CYAN}║${blspaces}${banner_text}${brspaces}║${M_RESET}${eol}"$'\n'
    _buf+="${pad}${M_BOLD}${M_CYAN}╚${border_fill}╝${M_RESET}${eol}"$'\n'
    _buf+="${pad}${eol}"$'\n'

    # Commit and version info (centered as a block)
    local info_labels=(
        "Current Script Commit :"
        "Master Script Commit  :"
        "Current XO Commit     :"
        "Master XO Commit      :"
        "Current Node          :"
    )
    local script_branch_str="" script_master_branch_str="" xo_branch_str="" xo_master_branch_str=""
    [[ -n "$MENU_SCRIPT_BRANCH" ]]        && script_branch_str=" (Branch: ${MENU_SCRIPT_BRANCH})"
    [[ -n "$MENU_SCRIPT_MASTER_BRANCH" ]] && script_master_branch_str=" (Branch: ${MENU_SCRIPT_MASTER_BRANCH})"
    [[ -n "$MENU_XO_BRANCH" ]]            && xo_branch_str=" (Branch: ${MENU_XO_BRANCH})"
    [[ -n "$MENU_XO_MASTER_BRANCH" ]]     && xo_master_branch_str=" (Branch: ${MENU_XO_MASTER_BRANCH})"
    local info_values=(
        "${MENU_SCRIPT_COMMIT}${script_branch_str}"
        "${MENU_SCRIPT_MASTER}${script_master_branch_str}"
        "${MENU_XO_COMMIT}${xo_branch_str}"
        "${MENU_XO_MASTER}${xo_master_branch_str}"
        "$MENU_NODE_VERSION"
    )
    # Find the longest full line to compute a single centering offset
    local info_max_len=0
    for ((il=0; il<${#info_labels[@]}; il++)); do
        local full_len=$(( ${#info_labels[$il]} + 1 + ${#info_values[$il]} ))
        (( full_len > info_max_len )) && info_max_len=$full_len
    done
    local info_lpad=$(( (content_width - info_max_len) / 2 ))
    local info_pad=""
    (( info_lpad > 0 )) && printf -v info_pad '%*s' "$info_lpad" ''
    for ((il=0; il<${#info_labels[@]}; il++)); do
        local info_color="${M_YELLOW}"
        local label_color="${M_BOLD}"
        [[ $il -eq 4 ]] && info_color="${M_GREEN}"
        # Highlight the entire Master XO Commit line when an update is available
        if [[ $il -eq 3 && "$MENU_XO_COMMIT" != "N/A" && "$MENU_XO_MASTER" != "N/A" && "$MENU_XO_COMMIT" != "$MENU_XO_MASTER" ]]; then
            local xo_style="${M_BOLD}${M_REVERSE}${M_RED}"
            _buf+="${pad}${info_pad}${xo_style}⚠ ${info_labels[$il]} ${info_values[$il]}${M_RESET}${eol}"$'\n'
        else
            _buf+="${pad}${info_pad}${label_color}${info_labels[$il]}${M_RESET} ${info_color}${info_values[$il]}${M_RESET}${eol}"$'\n'
        fi
    done
    _buf+="${pad}${eol}"$'\n'

    # Separator
    local sep_fill
    printf -v sep_fill '%*s' "$content_width" ''
    sep_fill="${sep_fill// /─}"
    _buf+="${pad}${M_DIM}${sep_fill}${M_RESET}${eol}"$'\n'
    _buf+="${pad}${eol}"$'\n'

    # Menu items in 2 columns (left: indices 0-3, right: indices 4-6)
    local rows=$MENU_LEFT_COUNT
    for ((row=0; row<rows; row++)); do
        local line=""
        for ((col=0; col<2; col++)); do
            local idx
            if [[ $col -eq 0 ]]; then
                idx=$row
            else
                idx=$((MENU_LEFT_COUNT + row))
            fi

            # Skip if index out of range (right column has fewer items)
            if [[ $idx -ge $MENU_TOTAL ]]; then
                continue
            fi

            local prefix="  "
            local checkbox="[ ]"
            local name="${MENU_NAMES[$idx]}"
            local hint="${MENU_HINTS[$idx]}"

            # Cursor indicator
            if [[ $idx -eq $MENU_CURSOR ]]; then
                prefix="${M_BOLD}${M_BLUE}▸ ${M_RESET}"
            fi

            # Selection checkbox
            if [[ ${MENU_SELECTED[$idx]} -eq 1 ]]; then
                checkbox="${M_GREEN}[✓]${M_RESET}"
            fi

            # Build item string
            local item=""
            if [[ $idx -eq $MENU_CURSOR ]]; then
                item="${prefix}${checkbox} ${M_BOLD}${name}${M_RESET}"
            else
                item="${prefix}${checkbox} ${name}"
            fi

            # Add hint in dim text
            if [[ -n "$hint" ]]; then
                item="${item} ${M_DIM}${hint}${M_RESET}"
            fi

            # Pad left column to fixed width (based on visible characters only)
            if [[ $col -eq 0 ]]; then
                local visible_len=$((2 + 3 + 1 + ${#name}))
                if [[ -n "$hint" ]]; then
                    visible_len=$((visible_len + 1 + ${#hint}))
                fi
                local padding=$((col_width - visible_len))
                [[ $padding -lt 2 ]] && padding=2
                item="${item}$(printf '%*s' $padding '')"
            fi

            line="${line}${item}"
        done
        _buf+="${pad}${line}${eol}"$'\n'
    done

    _buf+="${pad}${eol}"$'\n'
    _buf+="${pad}${M_DIM}${sep_fill}${M_RESET}${eol}"$'\n'
    _buf+="${pad}${eol}"$'\n'

    # Count selections
    local sel_count=0
    for ((i=0; i<MENU_TOTAL; i++)); do
        [[ ${MENU_SELECTED[$i]} -eq 1 ]] && sel_count=$((sel_count + 1))
    done
    _buf+="${pad}${M_CYAN}Selected: ${M_GREEN}${sel_count}${M_RESET}${eol}"$'\n'
    _buf+="${pad}${eol}"$'\n'

    # Key legend
    _buf+="${pad}${M_YELLOW}↑↓←→ Navigate   SPACE Select/Deselect   ENTER Confirm   Q Quit${M_RESET}${eol}"$'\n'
    _buf+="${pad}${M_DIM}Legend: ${M_GREEN}[✓]${M_RESET}${M_DIM} selected  ${M_RESET}${M_DIM}[ ] not selected${M_RESET}${eol}"$'\n'

    # Erase any leftover lines from previous render
    _buf+=$'\033[J'
    printf '%s' "$_buf"
}

# Read a single keypress and return a key name
menu_read_key() {
    local key
    IFS= read -rsn1 key 2>/dev/null || true

    # Escape sequence (arrow keys, etc.)
    if [[ "$key" == $'\x1b' ]]; then
        local seq
        IFS= read -rsn1 -t 0.5 seq 2>/dev/null || true
        if [[ "$seq" == "[" ]] || [[ "$seq" == "O" ]]; then
            local code
            IFS= read -rsn1 -t 0.5 code 2>/dev/null || true
            case "$code" in
                A) echo "UP"; return ;;
                B) echo "DOWN"; return ;;
                C) echo "RIGHT"; return ;;
                D) echo "LEFT"; return ;;
            esac
        fi
        echo "ESCAPE"
        return
    fi

    case "$key" in
        ' ') echo "SPACE" ;;
        '') echo "ENTER" ;;
        q|Q) echo "QUIT" ;;
        *) echo "OTHER" ;;
    esac
}

# Get the column (0=left, 1=right) and row for a cursor index
menu_get_pos() {
    local idx=$1
    if [[ $idx -lt $MENU_LEFT_COUNT ]]; then
        MCOL=0
        MROW=$idx
    else
        MCOL=1
        MROW=$((idx - MENU_LEFT_COUNT))
    fi
}

# Convert column/row to cursor index
menu_set_cursor() {
    local col=$1 row=$2
    if [[ $col -eq 0 ]]; then
        MENU_CURSOR=$row
    else
        local target=$((MENU_LEFT_COUNT + row))
        if [[ $target -lt $MENU_TOTAL ]]; then
            MENU_CURSOR=$target
        fi
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
    if [[ ${MENU_SELECTED[2]} -eq 1 ]]; then
        menu_rename_config
    fi

    if [[ ${MENU_SELECTED[6]} -eq 1 ]]; then
        menu_edit_config
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
    if [[ ${MENU_SELECTED[4]} -eq 1 ]]; then
        check_required_commands
        check_not_root
        check_sudo
        check_systemctl
        load_config
        reconfigure_xo
    fi

    # Rebuild Xen Orchestra
    if [[ ${MENU_SELECTED[5]} -eq 1 ]]; then
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
    if [[ ${MENU_SELECTED[7]} -eq 1 ]]; then
        check_required_commands
        check_not_root
        check_sudo
        check_systemctl
        load_config
        restore_xo
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

    # Reset selection state
    MENU_CURSOR=0
    MENU_SELECTED=(0 0 0 0 0 0 0 0)

    # Gather version/commit info for header display
    menu_gather_info

    # Save terminal state (global so cleanup_menu trap can access it)
    saved_stty=$(stty -g 2>/dev/null) || saved_stty=""
    menu_hide_cursor
    stty -echo 2>/dev/null || true

    # Restore terminal on exit
    cleanup_menu() {
        menu_show_cursor
        [[ -n "$saved_stty" ]] && stty "$saved_stty" 2>/dev/null || stty echo 2>/dev/null
    }
    trap cleanup_menu EXIT
    trap 'draw_menu' WINCH

    clear
    draw_menu

    while true; do
        local key
        key=$(menu_read_key)

        case "$key" in
            UP)
                menu_get_pos $MENU_CURSOR
                local col_size
                if [[ $MCOL -eq 0 ]]; then
                    col_size=$MENU_LEFT_COUNT
                else
                    col_size=$MENU_RIGHT_COUNT
                fi
                local new_row=$(( (MROW - 1 + col_size) % col_size ))
                menu_set_cursor $MCOL $new_row
                ;;
            DOWN)
                menu_get_pos $MENU_CURSOR
                local col_size
                if [[ $MCOL -eq 0 ]]; then
                    col_size=$MENU_LEFT_COUNT
                else
                    col_size=$MENU_RIGHT_COUNT
                fi
                local new_row=$(( (MROW + 1) % col_size ))
                menu_set_cursor $MCOL $new_row
                ;;
            LEFT)
                menu_get_pos $MENU_CURSOR
                if [[ $MCOL -eq 1 ]]; then
                    local target_row=$MROW
                    [[ $target_row -ge $MENU_LEFT_COUNT ]] && target_row=$((MENU_LEFT_COUNT - 1))
                    menu_set_cursor 0 $target_row
                fi
                ;;
            RIGHT)
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
            --install|--update|--restore|--rebuild|--reconfigure|--proxy|--uninstall|--help)
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
        log_error "--non-interactive requires an explicit operation flag (--install, --update, --restore, --rebuild, --reconfigure, --proxy, --uninstall)"
        exit 1
    fi

    # Acquire exclusive lock for all mutating operations (not --help)
    if [[ "$OPERATION" != "--help" ]]; then
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
