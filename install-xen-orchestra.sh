#!/bin/bash
set -euo pipefail
trap 'log_error "Script failed at line $LINENO. If the service was stopped, run: sudo systemctl start xo-server"' ERR
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

set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# Check if sudo is available and user has sudo privileges
check_sudo() {
    if ! command -v sudo &> /dev/null; then
        log_error "sudo is not installed. Please install sudo first."
        exit 1
    fi

    if ! sudo -v &> /dev/null; then
        log_error "You need sudo privileges to run this script."
        log_error "Please ensure your user is in the sudoers file."
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
    NODE_VERSION=${NODE_VERSION:-20}
    SERVICE_USER=${SERVICE_USER:-xo}
    DEBUG_MODE=${DEBUG_MODE:-false}
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
        . /etc/os-release
        OS_ID="${ID}"
        OS_VERSION_ID="${VERSION_ID}"
    else
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
        if ! $PKG_INSTALL $BASE_PACKAGES libfuse2t64 2>/dev/null; then
            log_info "libfuse2t64 not available, trying libfuse2..."
            $PKG_INSTALL $BASE_PACKAGES libfuse2
        fi
        
    elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
        # Check if it's RHEL 10+ or similar where Redis is replaced by Valkey
        if [[ "$PKG_MANAGER" == "dnf" ]]; then
            # Try to install Redis first, fall back to Valkey
            if ! $PKG_INSTALL redis 2>/dev/null; then
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

# Install Node.js 20 LTS (includes npm v10)
install_nodejs() {
    log_info "Installing Node.js ${NODE_VERSION} LTS..."

    # Check if Node.js is already installed with correct version
    if command -v node &> /dev/null; then
        CURRENT_NODE=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
        if [[ "$CURRENT_NODE" == "$NODE_VERSION" ]]; then
            log_info "Node.js ${NODE_VERSION} is already installed: $(node -v)"
            if command -v npm &> /dev/null; then
                log_info "npm is available: $(npm -v)"
            fi
            return 0
        else
            log_warning "Node.js $(node -v) is installed, but version ${NODE_VERSION} is required"
        fi
    fi

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        # Install Node.js via NodeSource (includes npm)
        curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
        curl -fsSL https://rpm.nodesource.com/setup_${NODE_VERSION}.x | sudo -E bash -
        $PKG_INSTALL nodejs
    fi

    log_success "Node.js installed: $(node -v)"
    log_success "npm installed: $(npm -v)"
}

# Install Yarn
install_yarn() {
    log_info "Installing Yarn..."

    if command -v yarn &> /dev/null; then
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
            # Create with root group membership for full NFS access
            sudo useradd -r -m -s /bin/bash -G root,users "$SERVICE_USER" || true
            log_success "Service user created: $SERVICE_USER"
        else
            log_info "Service user $SERVICE_USER already exists"
            # Add to root and users groups for full privileges
            sudo usermod -a -G root,users "$SERVICE_USER" 2>/dev/null || true
        fi
        
        # Display UID/GID for reference
        local XO_UID=$(id -u "$SERVICE_USER" 2>/dev/null || echo "unknown")
        local XO_GID=$(id -g "$SERVICE_USER" 2>/dev/null || echo "unknown")
        log_info "Service user UID:GID is ${XO_UID}:${XO_GID}"
        log_info "Service user added to root group for NFS access"
    fi
}

# Start and enable Redis
setup_redis() {
    log_info "Setting up Redis..."

    # Try redis-server first, then valkey
    if systemctl list-unit-files | grep -q redis; then
        sudo systemctl enable redis-server || sudo systemctl enable redis || true
        sudo systemctl start redis-server || sudo systemctl start redis || true
    elif systemctl list-unit-files | grep -q valkey; then
        sudo systemctl enable valkey
        sudo systemctl start valkey
    fi

    # Verify Redis is running
    if redis-cli ping | grep -q PONG; then
        log_success "Redis is running"
    else
        log_error "Redis is not responding"
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

    # Set Node.js memory limits and limit parallel builds to prevent OOM
    local BUILD_ENV="NODE_OPTIONS='--max-old-space-size=4096' TURBO_CACHE=remote:r"
    
    # Run as service user if defined
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo -u "$SERVICE_USER" bash -c "cd '$INSTALL_DIR' && $BUILD_ENV yarn && $BUILD_ENV yarn build"
    else
        sudo bash -c "cd '$INSTALL_DIR' && $BUILD_ENV yarn && $BUILD_ENV yarn build"
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

# HTTP settings - listen directly on ports
[[http.listen]]
port = ${HTTP_PORT}

# HTTPS settings with self-signed certificate
[[http.listen]]
port = ${HTTPS_PORT}
cert = "${SSL_CERT_DIR}/${SSL_CERT_FILE}"
key = "${SSL_CERT_DIR}/${SSL_KEY_FILE}"

[remoteOptions]
mountsDir = '/run/xo-server/mounts'
useSudo = true
nfsOptions = 'vers=4.1,rw,nolock,sec=sys'
EOF

    # Set ownership if service user is defined
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo chown -R "$SERVICE_USER:root" /etc/xo-server
    fi

    log_success "Configuration written to $XO_CONFIG_FILE"
}

# Create systemd service
create_systemd_service() {
    log_info "Creating systemd service..."

    local NODE_PATH=$(which node)
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
Environment="${DEBUG_ENV}"
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

# Get current installed commit
get_installed_commit() {
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        # Run as service user to avoid git's dubious ownership check
        if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
            sudo -u "$SERVICE_USER" git -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null
        else
            git -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null
        fi
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
        # Read commit hash directly from backup's git repo (backups are owned by root)
        local BACKUP_COMMIT=""
        if [[ -d "$BACKUP/.git" ]]; then
            BACKUP_COMMIT=$(sudo git -C "$BACKUP" rev-parse HEAD 2>/dev/null | cut -c1-12 || true)
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
    read -r CHOICE

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
    read -r CONFIRM

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

    # Fix ownership
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo chown -R "$SERVICE_USER:root" "$INSTALL_DIR"
        sudo chmod -R g+rwX "$INSTALL_DIR"
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

    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo -u "$SERVICE_USER" git -C "$INSTALL_DIR" checkout .
        sudo -u "$SERVICE_USER" git -C "$INSTALL_DIR" fetch origin
        sudo -u "$SERVICE_USER" git -C "$INSTALL_DIR" checkout -B "$GIT_BRANCH" "origin/$GIT_BRANCH"
    else
        sudo git -C "$INSTALL_DIR" checkout .
        sudo git -C "$INSTALL_DIR" fetch origin
        sudo git -C "$INSTALL_DIR" checkout -B "$GIT_BRANCH" "origin/$GIT_BRANCH"
    fi

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
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        CURRENT_BRANCH=$(sudo -u "$SERVICE_USER" git -C "$INSTALL_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "$GIT_BRANCH")
    else
        CURRENT_BRANCH=$(sudo git -C "$INSTALL_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "$GIT_BRANCH")
    fi

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
    read -r CONFIRM

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
    SERVER_IP=$(hostname -I | awk '{print $1}')
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

    check_not_root
    check_sudo
    load_config
    detect_package_manager
    install_dependencies
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
    echo "  --help        Show this help message"
    echo ""
    echo "Configuration:"
    echo "  Copy sample-xo-config.cfg to xo-config.cfg and edit as needed."
    echo "  If xo-config.cfg is not found, it will be created automatically."
    echo "  To switch branches, edit GIT_BRANCH in xo-config.cfg and run --update."
    echo ""
}

# Main entry point
main() {
    case "${1:-}" in
        --update)
            check_not_root
            check_sudo
            load_config
            update_xo
            ;;
        --restore)
            check_not_root
            check_sudo
            load_config
            restore_xo
            ;;
        --rebuild)
            check_not_root
            check_sudo
            load_config
            rebuild_xo
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
