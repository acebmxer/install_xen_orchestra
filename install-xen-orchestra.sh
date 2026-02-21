#!/bin/bash
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

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."

    $PKG_UPDATE

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        $PKG_INSTALL build-essential redis-server libpng-dev git python3-minimal \
            libvhdi-utils lvm2 cifs-utils nfs-common ntfs-3g openssl curl ca-certificates gnupg
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
            nfs-utils ntfs-3g openssl curl
    fi

    log_success "System dependencies installed"
}

# Install Node.js 20 LTS
install_nodejs() {
    log_info "Installing Node.js ${NODE_VERSION} LTS..."

    # Check if Node.js is already installed with correct version
    if command -v node &> /dev/null; then
        CURRENT_NODE=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
        if [[ "$CURRENT_NODE" == "$NODE_VERSION" ]]; then
            log_info "Node.js ${NODE_VERSION} is already installed: $(node -v)"
            return 0
        else
            log_warning "Node.js $(node -v) is installed, but version ${NODE_VERSION} is required"
        fi
    fi

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        # Install Node.js via NodeSource
        curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
        curl -fsSL https://rpm.nodesource.com/setup_${NODE_VERSION}.x | sudo -E bash -
        $PKG_INSTALL nodejs
    fi

    log_success "Node.js installed: $(node -v)"
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
            sudo useradd -r -m -s /bin/bash "$SERVICE_USER" || true
            log_success "Service user created: $SERVICE_USER"
        else
            log_info "Service user $SERVICE_USER already exists"
        fi
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
        sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    fi

    log_success "Repository cloned to $INSTALL_DIR"
}

# Build Xen Orchestra
build_xo() {
    log_info "Building Xen Orchestra (this may take a while)..."

    # Run as service user if defined
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo -u "$SERVICE_USER" bash -c "cd '$INSTALL_DIR' && yarn && yarn build"
    else
        sudo bash -c "cd '$INSTALL_DIR' && yarn && yarn build"
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
        sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$SSL_CERT_DIR"
    fi

    log_success "SSL certificates generated in $SSL_CERT_DIR"
}

# Configure Xen Orchestra
configure_xo() {
    log_info "Configuring Xen Orchestra..."

    local XO_CONFIG_FILE="/etc/xo-server/config.toml"

    # Create config directory
    sudo mkdir -p /etc/xo-server

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

# Use sudo for NFS mounts (required for non-root user)
useSudo = true
EOF

    # Set ownership if service user is defined
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo chown -R "$SERVICE_USER:$SERVICE_USER" /etc/xo-server
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
Environment="${DEBUG_ENV}"
Environment="NODE_ENV=production"
WorkingDirectory=${INSTALL_DIR}/packages/xo-server
ExecStart=${NODE_PATH} ${XO_SERVER_PATH}
Restart=always
RestartSec=10
SyslogIdentifier=xo-server

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}
ReadWritePaths=/var/lib/xo-server
ReadWritePaths=/tmp
ReadWritePaths=/etc/xo-server

# Allow binding to privileged ports
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    # Create data directory
    sudo mkdir -p /var/lib/xo-server
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        sudo chown "$SERVICE_USER:$SERVICE_USER" /var/lib/xo-server
    fi

    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable xo-server

    log_success "Systemd service created and enabled"
}

# Configure sudo for non-root user
configure_sudo() {
    if [[ -n "$SERVICE_USER" ]] && [[ "$SERVICE_USER" != "root" ]]; then
        log_info "Configuring sudo for NFS mounts..."

        local SUDOERS_FILE="/etc/sudoers.d/xo-server"

        sudo tee "$SUDOERS_FILE" > /dev/null << EOF
# Allow xo-server user to mount/unmount without password
${SERVICE_USER} ALL=(root) NOPASSWD: /bin/mount, /bin/umount, /bin/findmnt
EOF

        sudo chmod 440 "$SUDOERS_FILE"
        log_success "Sudo configured for ${SERVICE_USER}"
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

    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local BACKUP_NAME="xo-backup-${TIMESTAMP}"
    local BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

    # Create backup (excluding node_modules to save space)
    sudo cp -r "$INSTALL_DIR" "$BACKUP_PATH"
    sudo rm -rf "${BACKUP_PATH}/node_modules"

    log_success "Backup created: $BACKUP_PATH"

    # Purge old backups, keep only the latest BACKUP_KEEP
    log_info "Cleaning old backups (keeping ${BACKUP_KEEP})..."
    ls -dt "${BACKUP_DIR}"/xo-backup-* 2>/dev/null | tail -n +$((BACKUP_KEEP + 1)) | sudo xargs -r rm -rf

    log_success "Old backups cleaned"
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
        sudo -u "$SERVICE_USER" git -C "$INSTALL_DIR" checkout "$GIT_BRANCH"
        sudo -u "$SERVICE_USER" git -C "$INSTALL_DIR" pull --ff-only origin "$GIT_BRANCH"
    else
        sudo git -C "$INSTALL_DIR" checkout .
        sudo git -C "$INSTALL_DIR" fetch origin
        sudo git -C "$INSTALL_DIR" checkout "$GIT_BRANCH"
        sudo git -C "$INSTALL_DIR" pull --ff-only origin "$GIT_BRANCH"
    fi

    # Rebuild
    build_xo

    # Start service
    log_info "Starting xo-server service..."
    sudo systemctl start xo-server

    log_success "Update completed successfully!"
    log_info "New commit: $(get_installed_commit | cut -c1-12)"
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
    echo "  - HTTP:  http://$(hostname -I | awk '{print $1}'):${HTTP_PORT}"
    echo "  - HTTPS: https://$(hostname -I | awk '{print $1}'):${HTTPS_PORT}"
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
    echo "  --help        Show this help message"
    echo ""
    echo "Configuration:"
    echo "  Copy sample-xo-config.cfg to xo-config.cfg and edit as needed."
    echo "  If xo-config.cfg is not found, it will be created automatically."
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
        --help)
            show_help
            ;;
        *)
            install_xo
            ;;
    esac
}

main "$@"
