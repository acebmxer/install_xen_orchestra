#!/bin/bash
#
# Xen Orchestra Installation Script for Ubuntu 24.04.3
# This script installs Xen Orchestra from source with all dependencies
# and configures it to run on ports 80 and 443 with SSL
#
# Usage:
#   ./install-xen-orchestra.sh          - Fresh installation
#   ./install-xen-orchestra.sh --upgrade - Upgrade existing installation
#

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Installation paths
XO_DIR="/opt/xen-orchestra"
CONFIG_DIR="$XO_DIR/packages/xo-server"
SSL_DIR="/etc/xo-ssl"

# Log function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

# Function to generate self-signed SSL certificate
generate_ssl_certificate() {
    log "Generating self-signed SSL certificate..."
    
    # Create SSL directory if it doesn't exist
    mkdir -p "$SSL_DIR"
    
    # Get server hostname and IP
    SERVER_HOSTNAME=$(hostname -f)
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    # Generate private key
    openssl genrsa -out "$SSL_DIR/key.pem" 2048 2>/dev/null
    
    # Generate certificate signing request and self-signed certificate
    openssl req -new -x509 -key "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.pem" -days 3650 \
        -subj "/C=US/ST=State/L=City/O=Xen Orchestra/OU=IT/CN=$SERVER_HOSTNAME" \
        -addext "subjectAltName=DNS:$SERVER_HOSTNAME,DNS:localhost,IP:$SERVER_IP" 2>/dev/null
    
    # Set proper permissions
    chmod 600 "$SSL_DIR/key.pem"
    chmod 644 "$SSL_DIR/cert.pem"
    chown -R xo:xo "$SSL_DIR"
    
    log "SSL certificate generated successfully"
    log "Certificate: $SSL_DIR/cert.pem"
    log "Private key: $SSL_DIR/key.pem"
    log "Valid for: 10 years"
}

# Function to check if ports are available
check_ports() {
    log "Checking if ports 80 and 443 are available..."
    
    for port in 80 443; do
        if netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then
            warn "Port $port appears to be in use"
            read -p "Do you want to continue anyway? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                error "Installation cancelled. Please free port $port and try again."
            fi
        else
            log "Port $port is available"
        fi
    done
}

# Function to upgrade Xen Orchestra
upgrade_xo() {
    log "Starting Xen Orchestra upgrade process..."
    
    if [ ! -d "$XO_DIR" ]; then
        error "Xen Orchestra is not installed at $XO_DIR. Run without --upgrade to install."
    fi
    
    # Stop the service
    log "Stopping Xen Orchestra service..."
    systemctl stop xo-server.service || warn "Service was not running"
    
    # Backup current installation
    BACKUP_DIR="/opt/xo-backup-$(date +%Y%m%d-%H%M%S)"
    log "Creating backup at $BACKUP_DIR..."
    cp -a "$XO_DIR" "$BACKUP_DIR"
    
    # Backup configuration
    if [ -f "$CONFIG_DIR/.xo-server.toml" ]; then
        cp "$CONFIG_DIR/.xo-server.toml" "$CONFIG_DIR/.xo-server.toml.backup.$(date +%Y%m%d-%H%M%S)"
    fi
    
    cd "$XO_DIR"
    
    # Pull latest changes
    log "Pulling latest changes from repository..."
    sudo -H -u xo git pull || error "Failed to pull latest changes"
    
    # Clean and reinstall dependencies
    log "Cleaning old dependencies..."
    sudo -H -u xo yarn cache clean
    
    log "Installing updated dependencies..."
    if ! sudo -H -u xo yarn install --ignore-engines; then
        error "Failed to install dependencies. Backup available at $BACKUP_DIR"
    fi
    
    # Rebuild
    log "Rebuilding Xen Orchestra..."
    if ! sudo -H -u xo yarn build; then
        error "Failed to build Xen Orchestra. Backup available at $BACKUP_DIR"
    fi
    
    # Verify the build
    if [ ! -f "$XO_DIR/packages/xo-server/dist/cli.mjs" ]; then
        error "Build verification failed. Backup available at $BACKUP_DIR"
    fi
    
    log "Build verification successful"
    
    # Restart the service
    log "Starting Xen Orchestra service..."
    systemctl start xo-server.service
    
    # Wait for service to start
    sleep 5
    
    if systemctl is-active --quiet xo-server.service; then
        log "Xen Orchestra upgrade completed successfully!"
        log "Backup of previous version: $BACKUP_DIR"
        echo ""
        echo "=========================================="
        echo -e "${GREEN}Upgrade Complete!${NC}"
        echo "=========================================="
        echo "Previous version backed up to: $BACKUP_DIR"
        echo "You can remove the backup once you verify everything works."
        echo ""
    else
        error "Service failed to start after upgrade. Check logs with: journalctl -u xo-server -n 50"
    fi
    
    exit 0
}

# Check for upgrade flag
if [ "$1" == "--upgrade" ]; then
    upgrade_xo
fi

log "Starting Xen Orchestra installation on Ubuntu 24.04.3"

# Check ports before installation
check_ports

# Update system
log "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install required dependencies including OpenSSL and net-tools
log "Installing system dependencies..."
apt-get install -y \
    build-essential \
    redis-server \
    libpng-dev \
    git \
    python3-minimal \
    libvhdi-utils \
    lvm2 \
    cifs-utils \
    curl \
    wget \
    gnupg \
    software-properties-common \
    nfs-common \
    openssl \
    net-tools

# Install Node.js 20.x (LTS)
log "Installing Node.js 20.x..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Verify Node.js and npm installation
log "Node.js version: $(node --version)"
log "npm version: $(npm --version)"

# Install Yarn package manager
log "Installing Yarn..."
npm install --global yarn

# Create xo user if it doesn't exist
if ! id "xo" &>/dev/null; then
    log "Creating 'xo' user..."
    useradd -m -s /bin/bash xo
fi

# Create installation directory
log "Creating installation directory: $XO_DIR"
mkdir -p "$XO_DIR"

# Set ownership of the directory to xo user before cloning
chown xo:xo "$XO_DIR"

# Clone Xen Orchestra repository
log "Cloning Xen Orchestra repository..."
if [ -d "$XO_DIR/.git" ]; then
    warn "Git repository already exists, pulling latest changes..."
    cd "$XO_DIR"
    sudo -u xo git pull
else
    sudo -H -u xo git clone -b master https://github.com/vatesfr/xen-orchestra "$XO_DIR"
fi

cd "$XO_DIR"

# Install dependencies
log "Installing Xen Orchestra dependencies (this may take a while)..."
if ! sudo -H -u xo yarn install --ignore-engines; then
    error "Failed to install dependencies. Check logs above for details."
fi

# Build Xen Orchestra
log "Building Xen Orchestra..."
if ! sudo -H -u xo yarn build; then
    error "Failed to build Xen Orchestra. Check logs above for details."
fi

# Verify the build was successful
if [ ! -f "$XO_DIR/packages/xo-server/dist/cli.mjs" ]; then
    error "Build verification failed: xo-server binary not found"
fi

log "Build verification successful"

# Generate SSL certificate
generate_ssl_certificate

# Create configuration directory
log "Creating configuration..."

# Backup existing config if it exists
if [ -f "$CONFIG_DIR/.xo-server.toml" ]; then
    warn "Existing configuration found, creating backup..."
    cp "$CONFIG_DIR/.xo-server.toml" "$CONFIG_DIR/.xo-server.toml.backup.$(date +%Y%m%d-%H%M%S)"
fi

# Create configuration file with both HTTP and HTTPS
cat > "$CONFIG_DIR/.xo-server.toml" << EOF
# Xen Orchestra Server Configuration

# HTTP listen address and port
[http]
  listen = [
    { port = 80 }
  ]

# HTTPS configuration with self-signed certificate
[https]
  listen = [
    { port = 443, cert = '$SSL_DIR/cert.pem', key = '$SSL_DIR/key.pem' }
  ]

# Redis server for session management and cache
[redis]
  uri = 'redis://localhost:6379/0'

# Default admin account (change password after first login!)
# Username: admin@admin.net
# Password: admin

EOF

chown xo:xo "$CONFIG_DIR/.xo-server.toml"

# Configure Redis to start on boot
log "Configuring Redis..."
systemctl enable redis-server
systemctl start redis-server

# Create systemd service file
log "Creating systemd service..."
cat > /etc/systemd/system/xo-server.service << EOF
[Unit]
Description=Xen Orchestra Server
After=network.target redis-server.service
Requires=redis-server.service

[Service]
Type=simple
User=xo
Group=xo
WorkingDirectory=$XO_DIR/packages/xo-server
ExecStart=/usr/bin/node --experimental-modules ./dist/cli.mjs
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=xo-server

# Security settings
NoNewPrivileges=true
PrivateTmp=true

# Allow binding to privileged ports (80, 443)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# Set proper permissions
chown -R xo:xo "$XO_DIR"

# Configure firewall if UFW is active
if command -v ufw &> /dev/null; then
    if ufw status | grep -q "Status: active"; then
        log "Configuring UFW firewall..."
        ufw allow 80/tcp comment 'Xen Orchestra HTTP'
        ufw allow 443/tcp comment 'Xen Orchestra HTTPS'
        log "Firewall rules added for ports 80 and 443"
    fi
fi

# Reload systemd and enable service
log "Enabling Xen Orchestra service..."
systemctl daemon-reload
systemctl enable xo-server.service

# Start the service
log "Starting Xen Orchestra..."
systemctl start xo-server.service

# Wait a moment for the service to start
sleep 5

# Check service status
if systemctl is-active --quiet xo-server.service; then
    log "Xen Orchestra service is running!"
else
    error "Xen Orchestra service failed to start. Check logs with: journalctl -u xo-server -n 50"
fi

# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')
SERVER_HOSTNAME=$(hostname -f)

# Print completion message
echo ""
echo "=========================================="
echo -e "${GREEN}Xen Orchestra Installation Complete!${NC}"
echo "=========================================="
echo ""
echo "Access Xen Orchestra at:"
echo "  HTTP:  http://$SERVER_IP"
echo "  HTTPS: https://$SERVER_IP"
echo "  or https://localhost (if on the server)"
echo ""
echo -e "${YELLOW}NOTE: You'll see a browser warning about the self-signed certificate.${NC}"
echo "This is normal. Click 'Advanced' and proceed to continue."
echo ""
echo "Default credentials:"
echo "  Username: admin@admin.net"
echo "  Password: admin"
echo ""
echo -e "${YELLOW}IMPORTANT SECURITY NOTES:${NC}"
echo "1. Change the default password immediately after login!"
echo "2. The service is running on both:"
echo "   - Port 80 (HTTP) - redirects to HTTPS"
echo "   - Port 443 (HTTPS) - with self-signed certificate"
echo "3. SSL Certificate details:"
echo "   - Certificate: $SSL_DIR/cert.pem"
echo "   - Private key: $SSL_DIR/key.pem"
echo "   - Valid for: 10 years"
echo "4. To use a trusted certificate (Let's Encrypt, etc.):"
echo "   - Replace the files in $SSL_DIR/"
echo "   - Restart the service: sudo systemctl restart xo-server"
echo ""
echo "Useful commands:"
echo "  Check status:  sudo systemctl status xo-server"
echo "  View logs:     sudo journalctl -u xo-server -f"
echo "  Restart:       sudo systemctl restart xo-server"
echo "  Stop:          sudo systemctl stop xo-server"
echo ""
echo "To upgrade Xen Orchestra in the future:"
echo "  sudo ./install-xen-orchestra.sh --upgrade"
echo ""
echo "Or manually:"
echo "  cd /opt/xen-orchestra"
echo "  sudo systemctl stop xo-server"
echo "  sudo -u xo git pull"
echo "  sudo -u xo yarn install --ignore-engines"
echo "  sudo -u xo yarn build"
echo "  sudo systemctl start xo-server"
echo ""
echo "=========================================="

log "Installation script completed successfully!"
