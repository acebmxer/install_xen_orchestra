#!/bin/bash
set -euo pipefail

# Enable debug mode if XO_DEBUG environment variable is set
if [[ "${XO_DEBUG:-0}" == "1" ]]; then
    set -x
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

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
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
        log_error "sudo is not installed. Please install sudo first."
        exit 1
    fi

    if ! sudo -v >/dev/null 2>&1; then
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

    # Attempt fast-forward pull
    local pull_err
    if ! pull_err=$(git -C "$SCRIPT_DIR" pull --ff-only origin "$current_branch" 2>&1); then
        log_warning "Script auto-update failed: $pull_err"
        log_warning "Local modifications detected in ${SCRIPT_DIR}."
        local reset_confirm
        read -n 1 -rp "$(echo -e "${YELLOW}[WARNING]${NC}") Reset to origin/${current_branch}? Local changes will be lost. (y/N) " reset_confirm < /dev/tty
        echo
        if [[ ! "$reset_confirm" =~ ^[Yy]$ ]]; then
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

    after=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null)

    if [[ "$before" != "$after" ]]; then
        log_success "Script updated to $(git -C "$SCRIPT_DIR" rev-parse --short HEAD). Restarting..."
        exec bash "$SCRIPT_PATH" "${ORIGINAL_ARGS[@]}"
    else
        log_info "Script is already up to date."
    fi
    return 0
}

# Check if systemctl is available
check_systemctl() {
    if ! command -v systemctl >/dev/null 2>&1; then
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
    NODE_VERSION=${NODE_VERSION:-24}
    SERVICE_USER=${SERVICE_USER:-root}
    DEBUG_MODE=${DEBUG_MODE:-false}
    BIND_ADDRESS=${BIND_ADDRESS:-0.0.0.0}
    REDIRECT_TO_HTTPS=${REDIRECT_TO_HTTPS:-false}
    REVERSE_PROXY_TRUST=${REVERSE_PROXY_TRUST:-false}
    REDIS_URI=${REDIS_URI:-}
    REDIS_SOCKET=${REDIS_SOCKET:-}
    DISABLE_WARNINGS=${DISABLE_WARNINGS:-false}
    DISABLE_LICENSE_CHECK=${DISABLE_LICENSE_CHECK:-false}

    # Validate configuration values
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
    $PKG_UPDATE

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
            $PKG_INSTALL $BASE_PACKAGES libfuse2t64
        else
            log_info "libfuse2t64 not available, installing libfuse2 instead..."
            $PKG_INSTALL $BASE_PACKAGES libfuse2
        fi
        
    elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
        # Check if it's RHEL 10+ or similar where Redis is replaced by Valkey
        if [[ "$PKG_MANAGER" == "dnf" ]]; then
            # Check if Redis package exists, fall back to Valkey if not
            if dnf list available 2>/dev/null | grep -q "^redis"; then
                $PKG_INSTALL redis
            else
                log_info "Redis not available, installing Valkey as replacement..."
                sudo dnf install -y epel-release || true
                sudo dnf config-manager --enable devel || true
                $PKG_INSTALL valkey valkey-compat-redis
            fi
        else
            $PKG_INSTALL redis
        fi
        $PKG_INSTALL libpng-devel git lvm2 cifs-utils make automake gcc gcc-c++ \
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
    TMP_DIR=$(mktemp -d)

    if ! curl -fsSL "$URL" -o "${TMP_DIR}/${FILENAME}"; then
        rm -rf "$TMP_DIR"
        return 1
    fi

    log_info "Installing Node.js v${FULL_VERSION}..."
    sudo tar -xJf "${TMP_DIR}/${FILENAME}" --strip-components=1 -C /usr/local/
    rm -rf "$TMP_DIR"

    # Ensure /usr/local/bin is usable (create symlinks into /usr/bin so
    # scripts that reference /usr/bin/node keep working)
    if [[ ! -e /usr/bin/node ]] || [[ "$(readlink -f /usr/bin/node 2>/dev/null)" != "/usr/local/bin/node" ]]; then
        sudo ln -sf /usr/local/bin/node /usr/bin/node
    fi
    if [[ ! -e /usr/bin/npm ]] || [[ "$(readlink -f /usr/bin/npm 2>/dev/null)" != "/usr/local/bin/npm" ]]; then
        sudo ln -sf /usr/local/bin/npm /usr/bin/npm
    fi
    if [[ ! -e /usr/bin/npx ]] || [[ "$(readlink -f /usr/bin/npx 2>/dev/null)" != "/usr/local/bin/npx" ]]; then
        sudo ln -sf /usr/local/bin/npx /usr/bin/npx
    fi

    return 0
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

    # If a specific minor/patch version was requested, try a direct download first
    if [[ "$NODE_VERSION" == *.* ]]; then
        if install_nodejs_binary "$NODE_VERSION"; then
            log_success "Node.js installed: $(node -v)"
            log_success "npm installed: $(npm -v)"
            return 0
        fi
        log_warning "Falling back to latest ${NODE_MAJOR}.x via NodeSource..."
    fi

    # Remove any previously installed binary-download Node.js so that
    # the NodeSource package owns /usr/bin/node without conflicts.
    if [[ -x /usr/local/bin/node ]]; then
        log_info "Removing previously installed Node.js binary from /usr/local..."
        sudo rm -f /usr/local/bin/node /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
        # Remove symlinks that install_nodejs_binary may have created
        for bin in node npm npx; do
            if [[ -L /usr/bin/$bin ]] && [[ "$(readlink -f /usr/bin/$bin 2>/dev/null)" == "/usr/local/bin/$bin" ]]; then
                sudo rm -f /usr/bin/$bin
            fi
        done
    fi

    # Install latest in the major series via NodeSource
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
        curl -fsSL https://rpm.nodesource.com/setup_${NODE_MAJOR}.x | sudo -E bash -
        $PKG_INSTALL nodejs
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

    sudo npm install -g yarn

    log_success "Yarn installed: $(yarn -v)"
}

# Create service user if needed
create_service_user() {
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        if ! id "$SERVICE_USER" &>/dev/null; then
            log_info "Creating service user: $SERVICE_USER"
            # Create with root group membership for NFS/mount operations
            sudo useradd -r -m -s /bin/bash -G root "$SERVICE_USER" || true
            log_success "Service user created: $SERVICE_USER"
        else
            log_info "Service user $SERVICE_USER already exists"
            # Ensure user is in root group for mount operations
            sudo usermod -a -G root "$SERVICE_USER" 2>/dev/null || true
        fi

        # Display UID/GID for reference
        local XO_UID=$(id -u "$SERVICE_USER" 2>/dev/null || echo "unknown")
        local XO_GID=$(id -g "$SERVICE_USER" 2>/dev/null || echo "unknown")
        log_info "Service user UID:GID is ${XO_UID}:${XO_GID}"
        log_info "Service user configured for NFS/mount operations"
    fi
}

# Start and enable Redis
setup_redis() {
    log_info "Setting up Redis..."

    check_systemctl

    # Try redis-server first, then valkey
    if systemctl list-unit-files 2>/dev/null | grep -q redis; then
        sudo systemctl enable redis-server 2>/dev/null || sudo systemctl enable redis 2>/dev/null || true
        sudo systemctl start redis-server 2>/dev/null || sudo systemctl start redis 2>/dev/null || true
    elif systemctl list-unit-files 2>/dev/null | grep -q valkey; then
        sudo systemctl enable valkey 2>/dev/null || true
        sudo systemctl start valkey 2>/dev/null || true
    else
        log_warning "Neither redis nor valkey service found in systemd units"
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

    sudo mkdir -p "$(dirname "$INSTALL_DIR")"

    log_info "Cloning Xen Orchestra (branch: $GIT_BRANCH)..."
    sudo git clone -b "$GIT_BRANCH" https://github.com/vatesfr/xen-orchestra "$INSTALL_DIR"

    # Set ownership if service user is defined
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo chown -R "$SERVICE_USER:root" "$INSTALL_DIR"
        sudo chmod -R g+rwX "$INSTALL_DIR"
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
        sudo swapoff "$SWAP_FILE" 2>/dev/null || true
        sudo rm -f "$SWAP_FILE"
    fi
    
    # Create swap file
    sudo fallocate -l ${MIN_SWAP_MB}M "$SWAP_FILE" 2>/dev/null || sudo dd if=/dev/zero of="$SWAP_FILE" bs=1M count=$MIN_SWAP_MB status=progress
    sudo chmod 600 "$SWAP_FILE"
    sudo mkswap "$SWAP_FILE"
    sudo swapon "$SWAP_FILE"
    
    # Make it persistent across reboots
    if ! grep -q "$SWAP_FILE" /etc/fstab 2>/dev/null; then
        echo "$SWAP_FILE none swap sw 0 0" | sudo tee -a /etc/fstab > /dev/null
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
            sudo -u "$SERVICE_USER" rm -rf "$INSTALL_DIR/node_modules/.cache/turbo" 2>/dev/null || true
            sudo -u "$SERVICE_USER" rm -rf "$INSTALL_DIR/.turbo" 2>/dev/null || true
        else
            sudo rm -rf "$INSTALL_DIR/node_modules/.cache/turbo" 2>/dev/null || true
            sudo rm -rf "$INSTALL_DIR/.turbo" 2>/dev/null || true
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

    # Run as service user if defined
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo -u "$SERVICE_USER" bash -c "cd '$INSTALL_DIR' && NODE_OPTIONS='$NODE_OPTIONS' TURBO_CACHE='$TURBO_CACHE' yarn && NODE_OPTIONS='$NODE_OPTIONS' TURBO_CACHE='$TURBO_CACHE' yarn build $CONCURRENCY_FLAG"
    else
        sudo bash -c "cd '$INSTALL_DIR' && NODE_OPTIONS='$NODE_OPTIONS' TURBO_CACHE='$TURBO_CACHE' yarn && NODE_OPTIONS='$NODE_OPTIONS' TURBO_CACHE='$TURBO_CACHE' yarn build $CONCURRENCY_FLAG"
    fi

    log_success "Xen Orchestra built successfully"
}

# Generate self-signed SSL certificate
generate_ssl_certificate() {
    log_info "Generating self-signed SSL certificate..."

    sudo mkdir -p "$SSL_CERT_DIR"

    if [[ -f "${SSL_CERT_DIR}/${SSL_CERT_FILE}" ]] && [[ -f "${SSL_CERT_DIR}/${SSL_KEY_FILE}" ]]; then
        log_info "SSL certificates already exist. Skipping generation."
        return 0
    fi

    sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "${SSL_CERT_DIR}/${SSL_KEY_FILE}" \
        -out "${SSL_CERT_DIR}/${SSL_CERT_FILE}" \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=IT/CN=xen-orchestra"

    # Set permissions
    sudo chmod 600 "${SSL_CERT_DIR}/${SSL_KEY_FILE}"
    sudo chmod 644 "${SSL_CERT_DIR}/${SSL_CERT_FILE}"

    # Set ownership if service user is defined
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo chown -R "$SERVICE_USER:root" "$SSL_CERT_DIR"
    fi

    log_success "SSL certificates generated in $SSL_CERT_DIR"
}

# Configure Xen Orchestra
configure_xo() {
    log_info "Configuring Xen Orchestra..."

    local XO_CONFIG_FILE="/etc/xo-server/config.toml"

    # Create config directory
    sudo mkdir -p /etc/xo-server
    
    # Create mounts directory with proper permissions
    # Note: /run/xo-server is tmpfs and will be recreated by systemd on boot
    sudo mkdir -p /run/xo-server/mounts
    sudo chmod 755 /run/xo-server/mounts
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo chown -R "$SERVICE_USER:root" /run/xo-server
        sudo chmod 775 /run/xo-server/mounts
    fi

    # Create configuration file
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

    # Set ownership if service user is defined
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo chown -R "$SERVICE_USER:root" /etc/xo-server
    fi

    # Create VDDK library directory expected by xo-server for VMware V2V import
    # XO extracts the VDDK tar.gz here when uploaded via the UI
    sudo mkdir -p /usr/local/lib/vddk
    sudo chmod 755 /usr/local/lib/vddk

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

    sudo tee /etc/systemd/system/xo-server.service > /dev/null << EOF
[Unit]
Description=Xen Orchestra Server
After=network-online.target redis.service
Wants=network-online.target

[Service]
Type=simple
User=${EXEC_USER}
Group=root
SupplementaryGroups=root
$(if [[ -n "$DEBUG_ENV" ]]; then echo "Environment=\"${DEBUG_ENV}\""; fi)
Environment="NODE_ENV=production"
WorkingDirectory=${INSTALL_DIR}/packages/xo-server
ExecStartPre=/bin/mkdir -p /run/xo-server/mounts
ExecStartPre=/bin/chmod 775 /run/xo-server/mounts
ExecStart=${NODE_PATH} ${XO_SERVER_PATH}
Restart=always
RestartSec=10
SyslogIdentifier=xo-server

# Runtime directory
RuntimeDirectory=xo-server
RuntimeDirectoryMode=0775

# Allow binding to privileged ports and mounting
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER CAP_SETUID CAP_SETGID CAP_AUDIT_WRITE

[Install]
WantedBy=multi-user.target
EOF

    # Create data directory
    sudo mkdir -p /var/lib/xo-server
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo chown "$SERVICE_USER:root" /var/lib/xo-server
        sudo chmod 775 /var/lib/xo-server
    fi

    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable xo-server

    log_success "Systemd service created and enabled"
}

# Configure sudo for non-root user
configure_sudo() {
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        log_info "Configuring sudo for ${SERVICE_USER} with root-equivalent privileges..."

        local SUDOERS_FILE="/etc/sudoers.d/xo-server-${SERVICE_USER}"

        sudo tee "$SUDOERS_FILE" > /dev/null << EOF
# Allow ${SERVICE_USER} user to mount/unmount and manage files with root privileges
Defaults:${SERVICE_USER} !requiretty
${SERVICE_USER} ALL=(root) NOPASSWD:SETENV: /bin/mount, /usr/bin/mount, /bin/umount, /usr/bin/umount, /bin/findmnt, /usr/bin/findmnt, /sbin/mount.nfs, /usr/sbin/mount.nfs, /sbin/mount.nfs4, /usr/sbin/mount.nfs4, /sbin/umount.nfs, /usr/sbin/umount.nfs, /sbin/umount.nfs4, /usr/sbin/umount.nfs4, /bin/mkdir, /usr/bin/mkdir, /bin/chmod, /usr/bin/chmod, /bin/chown, /usr/bin/chown
EOF

        sudo chmod 440 "$SUDOERS_FILE"
        
        # Remove setuid bit from mount.nfs to avoid conflicts with sudo
        log_info "Ensuring NFS mount helpers use sudo..."
        for nfs_mount in /sbin/mount.nfs /usr/sbin/mount.nfs /sbin/mount.nfs4 /usr/sbin/mount.nfs4; do
            if [[ -f "$nfs_mount" ]]; then
                sudo chmod u-s "$nfs_mount" 2>/dev/null || true
            fi
        done
        
        log_success "Sudo configured for ${SERVICE_USER} with elevated privileges"
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
    if [[ -d "$INSTALL_DIR/.git" ]]; then
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

    sudo mkdir -p "$BACKUP_DIR"

    local TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
    local BACKUP_NAME="xo-backup-${TIMESTAMP}"
    local BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

    # Create backup (excluding node_modules to save space)
    sudo cp -r "$INSTALL_DIR" "$BACKUP_PATH"
    sudo rm -rf "${BACKUP_PATH}/node_modules"

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
            sudo rm -rf "${ALL_BACKUPS[$idx]}"
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
        DATETIME=$(date -d "$RAW_DT" +"%Y-%m-%d %I:%M:%S %p %Z" 2>/dev/null || echo "${RAW_DT% UTC}")
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
    echo -n "Enter the number of the backup to restore [1-${TOTAL}], or 'q' to quit: "
    read -t 300 -r CHOICE || { log_error "Input timeout"; exit 1; }

    if [[ "$CHOICE" == "q" ]] || [[ "$CHOICE" == "Q" ]]; then
        log_info "Restore cancelled."
        exit 0
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
    echo -n "Are you sure? [y/N]: "
    read -t 300 -r CONFIRM || { log_error "Input timeout"; exit 1; }

    if [[ "$CONFIRM" != "y" ]] && [[ "$CONFIRM" != "Y" ]]; then
        log_info "Restore cancelled."
        exit 0
    fi

    # Stop the service
    log_info "Stopping xo-server service..."
    sudo systemctl stop xo-server || true

    # Remove current installation
    log_info "Removing current installation..."
    sudo rm -rf "$INSTALL_DIR"

    # Copy backup into place
    log_info "Restoring from backup: $SELECTED_NAME"
    sudo cp -r "$SELECTED_BACKUP" "$INSTALL_DIR"

    # Fix ownership to match current SERVICE_USER
    local DIR_OWNER
    DIR_OWNER=$(stat -c '%U' "$INSTALL_DIR" 2>/dev/null)
    if [[ "$SERVICE_USER" != "$DIR_OWNER" ]]; then
        log_info "Updating directory ownership from ${DIR_OWNER} to ${SERVICE_USER}..."
        if [[ "$SERVICE_USER" == "root" ]]; then
            sudo chown -R root:root "$INSTALL_DIR"
        else
            sudo chown -R "$SERVICE_USER:root" "$INSTALL_DIR"
            sudo chmod -R g+rwX "$INSTALL_DIR"
        fi
    fi

    # Rebuild — node_modules are excluded from backups
    log_info "Rebuilding Xen Orchestra (node_modules were excluded from backup)..."
    build_xo

    # Regenerate the systemd service file to pick up any script changes
    create_systemd_service

    # Start the service
    log_info "Starting xo-server service..."
    sudo systemctl start xo-server
    sleep 3

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

# Update Xen Orchestra
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

    # Stop service
    log_info "Stopping xo-server service..."
    sudo systemctl stop xo-server || true

    # Create backup
    create_backup

    # Update repository
    log_info "Pulling latest changes..."

    install_dir_git checkout .
    install_dir_git fetch origin
    install_dir_git checkout -B "$GIT_BRANCH" "origin/$GIT_BRANCH"

    # Fix ownership if SERVICE_USER changed since initial install
    local DIR_OWNER
    DIR_OWNER=$(stat -c '%U' "$INSTALL_DIR" 2>/dev/null)
    if [[ "$SERVICE_USER" != "$DIR_OWNER" ]]; then
        log_info "Updating directory ownership from ${DIR_OWNER} to ${SERVICE_USER}..."
        if [[ "$SERVICE_USER" == "root" ]]; then
            sudo chown -R root:root "$INSTALL_DIR"
        else
            sudo chown -R "$SERVICE_USER:root" "$INSTALL_DIR"
        fi
    fi

    # Ensure Node.js version matches config (upgrade if needed)
    install_nodejs

    # Rebuild with clean cache to ensure fresh build
    build_xo clean

    # Regenerate the systemd service file to pick up any script changes
    create_systemd_service

    # Start service
    log_info "Starting xo-server service..."
    sudo systemctl start xo-server

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
    echo -n "Continue? [y/N]: "
    read -t 300 -r CONFIRM || { log_error "Input timeout"; exit 1; }

    if [[ "$CONFIRM" != "y" ]] && [[ "$CONFIRM" != "Y" ]]; then
        log_info "Rebuild cancelled."
        exit 0
    fi

    # Stop the service before touching anything
    log_info "Stopping xo-server service..."
    sudo systemctl stop xo-server || true

    # Backup current installation (node_modules excluded, same as update)
    create_backup

    # Wipe current installation directory
    log_info "Removing current installation directory..."
    sudo rm -rf "$INSTALL_DIR"

    # Fresh clone of the same branch
    log_info "Cloning Xen Orchestra (branch: ${CURRENT_BRANCH})..."
    sudo mkdir -p "$(dirname "$INSTALL_DIR")"
    sudo git clone -b "$CURRENT_BRANCH" https://github.com/vatesfr/xen-orchestra "$INSTALL_DIR"

    # Restore ownership
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo chown -R "$SERVICE_USER:root" "$INSTALL_DIR"
        sudo chmod -R g+rwX "$INSTALL_DIR"
    fi

    # Ensure Node.js version matches config (upgrade if needed)
    install_nodejs

    # Clean build to ensure no stale artefacts
    build_xo clean

    # Regenerate the systemd service file to pick up any script changes
    create_systemd_service

    # Restart the service
    log_info "Starting xo-server service..."
    sudo systemctl start xo-server
    sleep 3

    local NEW_COMMIT
    NEW_COMMIT=$(get_installed_commit)

    echo ""
    echo "=============================================="
    log_success "Rebuild completed successfully!"
    echo "=============================================="
    log_info "Branch:      ${CURRENT_BRANCH}"
    log_info "New commit:  ${NEW_COMMIT:0:12}"

    if systemctl is-active --quiet xo-server; then
        log_success "xo-server is running"
    else
        log_warning "xo-server may have failed to start. Check: sudo systemctl status xo-server"
    fi

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
    echo ""
    log_warning "Database and user data in /var/lib/xo-server will NOT be affected."
    echo ""
    echo -n "Continue? [y/N]: "
    read -t 300 -r CONFIRM || { log_error "Input timeout"; exit 1; }

    if [[ "$CONFIRM" != "y" ]] && [[ "$CONFIRM" != "Y" ]]; then
        log_info "Reconfiguration cancelled."
        exit 0
    fi

    # Stop the service
    log_info "Stopping xo-server service..."
    sudo systemctl stop xo-server || true

    # Backup current config file
    if [[ -f "/etc/xo-server/config.toml" ]]; then
        log_info "Backing up current configuration..."
        sudo cp /etc/xo-server/config.toml /etc/xo-server/config.toml.backup-$(date +%Y%m%d-%H%M%S)
        log_success "Backup created"
    fi

    # Regenerate configuration
    configure_xo

    # Regenerate systemd service
    create_systemd_service

    # Reload systemd daemon
    log_info "Reloading systemd daemon..."
    sudo systemctl daemon-reload

    # Start the service
    log_info "Starting xo-server service..."
    sudo systemctl start xo-server
    sleep 3

    echo ""
    echo "=============================================="
    log_success "Reconfiguration completed successfully!"
    echo "=============================================="

    if systemctl is-active --quiet xo-server; then
        log_success "xo-server is running"
    else
        log_warning "xo-server may have failed to start. Check: sudo systemctl status xo-server"
    fi

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
    sudo systemctl start xo-server

    # Wait a moment for the service to start
    sleep 3

    if systemctl is-active --quiet xo-server; then
        log_success "xo-server is running"
    else
        log_warning "xo-server may have failed to start. Check: sudo systemctl status xo-server"
    fi
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
        $PKG_UPDATE
        $PKG_INSTALL expect
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

    read -sp "Host password: " HOST_PASSWORD
    echo ""
    if [[ -z "$HOST_PASSWORD" ]]; then
        log_error "Host password is required"
        exit 1
    fi

    # Test SSH connection
    log_info "Testing SSH connection to $HOST_USERNAME@$POOL_MASTER_IP..."
    if ! sshpass -p "$HOST_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$HOST_USERNAME@$POOL_MASTER_IP" "echo 'Connection successful'" &>/dev/null; then
        # Try installing sshpass if not available
        if ! command -v sshpass &> /dev/null; then
            log_info "Installing sshpass..."
            $PKG_INSTALL sshpass
            # Retry connection
            if ! sshpass -p "$HOST_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$HOST_USERNAME@$POOL_MASTER_IP" "echo 'Connection successful'" &>/dev/null; then
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

    read -sp "Xen Orchestra login password: " XO_PASSWORD
    echo ""
    if [[ -z "$XO_PASSWORD" ]]; then
        log_error "Xen Orchestra password is required"
        exit 1
    fi

    # Create expect script for proxy installation
    log_info "Creating installation script..."

    TEMP_SCRIPT=$(mktemp)
    cat > "$TEMP_SCRIPT" << 'EXPECT_SCRIPT_END'
#!/usr/bin/expect -f

set timeout 600
set pool_master [lindex $argv 0]
set username [lindex $argv 1]
set password [lindex $argv 2]
set proxy_ip [lindex $argv 3]
set ntp_server [lindex $argv 4]
set xo_username [lindex $argv 5]
set xo_password [lindex $argv 6]

# Variables to capture output
set proxy_uuid ""
set auth_token ""
set actual_proxy_ip ""

log_user 1

# Connect to pool master
spawn ssh -o StrictHostKeyChecking=no $username@$pool_master

# Handle password prompt
expect {
    "password:" {
        send "$password\r"
    }
}

# Wait for shell prompt and run installer
expect {
    -re ".*#" {
        send "bash -c \"\$(wget -qO- https://xoa.io/proxy/deploy)\"\r"
    }
}

# Handle installer prompts - more specific patterns
expect {
    -re "IP address\\? \\\[dhcp\\\]" {
        if {$proxy_ip eq "dhcp" || $proxy_ip eq "DHCP"} {
            send "\r"
        } else {
            send "$proxy_ip\r"
        }
        exp_continue
    }
    -re "Custom NTP servers.*\\? \\\[\\\]" {
        if {$ntp_server eq ""} {
            send "\r"
        } else {
            send "$ntp_server\r"
        }
        exp_continue
    }
    -re "Xen Orchestra \\(XO\\) address\\?" {
        send "http://localhost\r"
        exp_continue
    }
    -re "Your Xen Orchestra account \\(email\\)\\?" {
        send "$xo_username\r"
        exp_continue
    }
    -re "Your Xen Orchestra account password\\?" {
        send "$xo_password\r"
        exp_continue
    }
    -re "XO Proxy Appliance IP address: (\[0-9.\]+)" {
        set actual_proxy_ip $expect_out(1,string)
        exp_continue
    }
    -re "UUID: (\[a-f0-9-\]+)" {
        set proxy_uuid $expect_out(1,string)
        exp_continue
    }
    -re "authentication token: (\[a-zA-Z0-9_-\]+)" {
        set auth_token $expect_out(1,string)
        exp_continue
    }
    -re "token: (\[a-zA-Z0-9_-\]+)" {
        set auth_token $expect_out(1,string)
        exp_continue
    }
    -re ".*#" {
        # Back at prompt, installation complete
    }
    timeout {
        send_user "\nTimeout waiting for installer\n"
    }
    eof {
    }
}

# Exit SSH session
send "exit\r"
expect eof

# Output captured values
puts "\nCAPTURED_VALUES:"
puts "PROXY_IP=$actual_proxy_ip"
puts "PROXY_UUID=$proxy_uuid"
puts "AUTH_TOKEN=$auth_token"
EXPECT_SCRIPT_END

    chmod +x "$TEMP_SCRIPT"

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
        sudo npm i -g xo-cli
        log_success "xo-cli installed"
    fi

    # Register xo-cli with local Xen Orchestra
    log_info "Registering xo-cli with Xen Orchestra..."

    # Create a temporary expect script for xo-cli registration
    XO_CLI_SCRIPT=$(mktemp)
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
        if sshpass -p "$HOST_PASSWORD" ssh -o StrictHostKeyChecking=no "$HOST_USERNAME@$POOL_MASTER_IP" 'bash -s' << 'REMOTE_LICENSE_PATCH'
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

# Show help
show_help() {
    echo "Xen Orchestra Installation Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --update      Update existing installation"
    echo "  --restore     Restore a previous backup interactively"
    echo "  --rebuild     Fresh clone + clean build on the current branch (backup taken first)"
    echo "  --reconfigure Regenerate configuration and systemd service from xo-config.cfg"
    echo "  --proxy       Install XO Proxy on a Xen pool master"
    echo "  --help        Show this help message"
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

# Main entry point
main() {
    # Self-update before doing anything (skip for --help to avoid delays)
    if [[ "${1:-}" != "--help" ]]; then
        self_update_script
    fi

    case "${1:-}" in
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
        --help)
            show_help
            ;;
        *)
            install_xo
            ;;
    esac
}

main "$@"
