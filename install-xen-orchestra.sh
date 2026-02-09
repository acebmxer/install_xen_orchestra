#!/usr/bin/env bash
set -euo pipefail

# install-xen-orchestra.sh
# Usage: ./install-xen-orchestra.sh [--update]
# - Must NOT be run as root. The script will use sudo when needed.

SCRIPT_NAME=$(basename "$0")

if [ "$(id -u)" -eq 0 ]; then
	echo "Do NOT run $SCRIPT_NAME as root. Run it as a regular user with sudo privileges." >&2
	exit 1
fi

# Determine the invoking user (supports sudo invocation)
if [ -n "${SUDO_USER-}" ]; then
	RUN_USER="$SUDO_USER"
else
	RUN_USER="$USER"
fi

RUN_HOME=$(eval echo "~$RUN_USER")
XO_DIR="$RUN_HOME/xen-orchestra"
XO_SERVER_DIR="$XO_DIR/packages/xo-server"
CONFIG_DIR="$RUN_HOME/.config/xo-server"
CERT_DIR="$CONFIG_DIR/certs"

UPDATE_ONLY=false
if [ "${1-}" = "--update" ]; then
	UPDATE_ONLY=true
fi

echo "Running as user: $RUN_USER (home: $RUN_HOME)"

# Ensure sudo is available
if ! command -v sudo >/dev/null 2>&1; then
	echo "sudo not found - please install sudo and re-run this script." >&2
	exit 1
fi

echo "Updating apt and installing base packages (this requires your sudo password)..."
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
	build-essential redis-server libpng-dev git python3-minimal libvhdi-utils lvm2 cifs-utils nfs-common ntfs-3g openssl ca-certificates curl gnupg lsb-release apt-transport-https software-properties-common libcap2-bin

# Ensure Redis is enabled and running
sudo systemctl enable --now redis.service
if ! sudo -n true 2>/dev/null; then
	echo "Warning: sudo may prompt for password during the run (that's expected)."
fi

# Stop common web servers if they occupy ports 80/443 to free them
echo "Checking ports 80/443 and stopping common services if needed..."
for svc in apache2 nginx caddy httpd; do
	if sudo systemctl is-active --quiet "$svc" 2>/dev/null; then
		echo "Stopping $svc to free ports 80/443..."
		sudo systemctl stop "$svc" || true
		sudo systemctl disable "$svc" || true
	fi
done

check_port_free() {
	local port=$1
	if ss -ltn "sport = :$port" | grep -q LISTEN; then
		return 1
	fi
	return 0
}

for p in 80 443; do
	if ! check_port_free "$p"; then
		echo "Port $p is in use. Please free it and re-run the script." >&2
		echo "You may re-run after stopping services that bind to these ports." >&2
		exit 1
	fi
done

# Install Node.js (LTS v20.x) via NodeSource if node not present or old
if ! command -v node >/dev/null 2>&1 || [ "$(node -v | sed 's/v//;s/\..*//')" -lt 20 ]; then
	echo "Installing Node.js LTS (20.x)..."
	curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
	sudo apt-get install -y nodejs
fi

# Enable corepack (provides yarn) and activate yarn for the user
echo "Enabling corepack and preparing yarn for $RUN_USER..."
sudo -u "$RUN_USER" corepack enable || true
sudo -u "$RUN_USER" corepack prepare yarn@stable --activate || true

# Give node the capability to bind to low ports (443) without root.
NODE_PATH=$(command -v node || true)
if [ -n "$NODE_PATH" ]; then
	echo "Granting node the ability to bind privileged ports (setcap)..."
	sudo setcap 'cap_net_bind_service=+ep' "$NODE_PATH" || true
fi

# Clone or update the repository
if [ ! -d "$XO_DIR/.git" ]; then
	echo "Cloning xen-orchestra into $XO_DIR..."
	sudo -u "$RUN_USER" git clone -b master https://github.com/vatesfr/xen-orchestra "$XO_DIR"
	sudo chown -R "$RUN_USER":"$RUN_USER" "$XO_DIR"
else
	echo "xen-orchestra already exists at $XO_DIR"
fi

if [ "$UPDATE_ONLY" = true ]; then
	echo "--update requested: checking remote commit..."
	cd "$XO_DIR"
	LOCAL_COMMIT=$(git rev-parse HEAD)
	REMOTE_COMMIT=$(git ls-remote https://github.com/vatesfr/xen-orchestra.git refs/heads/master | awk '{print $1}')
	echo "Local: $LOCAL_COMMIT\nRemote: $REMOTE_COMMIT"
	if [ "$LOCAL_COMMIT" = "$REMOTE_COMMIT" ]; then
		echo "Already up to date. No update needed."
		exit 0
	else
		echo "Remote is different: performing update..."
		sudo -u "$RUN_USER" git -C "$XO_DIR" fetch --all
		sudo -u "$RUN_USER" git -C "$XO_DIR" reset --hard origin/master
		sudo -u "$RUN_USER" bash -lc "cd $XO_DIR && yarn && yarn build"
		echo "Restarting xo-server systemd service if present..."
		sudo systemctl daemon-reload || true
		sudo systemctl restart xo-server || true
		echo "Update completed."
		exit 0
	fi
fi

# Install dependencies and build
echo "Installing yarn dependencies and building xen-orchestra (this may take a while)..."
sudo -u "$RUN_USER" bash -lc "cd '$XO_DIR' && yarn"
sudo -u "$RUN_USER" bash -lc "cd '$XO_DIR' && yarn build"

# Prepare configuration and certificates
echo "Creating configuration and TLS certificates..."
sudo -u "$RUN_USER" mkdir -p "$CONFIG_DIR"
sudo -u "$RUN_USER" mkdir -p "$CERT_DIR"

CERT_KEY="$CERT_DIR/xo.key.pem"
CERT_CRT="$CERT_DIR/xo.crt.pem"

if [ ! -f "$CERT_KEY" ] || [ ! -f "$CERT_CRT" ]; then
	echo "Generating self-signed certificate for Xen Orchestra..."
	sudo openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
		-keyout "$CERT_KEY" -out "$CERT_CRT" \
		-subj "/C=US/ST=State/L=City/O=XO/OU=XO/CN=$(hostname -f)"
	sudo chown -R "$RUN_USER":"$RUN_USER" "$CONFIG_DIR"
	sudo chmod 700 "$CONFIG_DIR"
	sudo chmod 600 "$CERT_KEY"
	sudo chmod 644 "$CERT_CRT"
fi

# Create a minimal config.toml that enables HTTP (80) and HTTPS (443)
echo "Writing configuration file to $CONFIG_DIR/config.toml"
cat > /tmp/xo-server-config.toml <<EOF
# Auto-generated by install-xen-orchestra.sh
[http]
redirectToHttps = true

[[http.listen]]
hostname = "0.0.0.0"
port = 80

[[http.listen]]
hostname = "0.0.0.0"
port = 443
autoCert = false
cert = "$CERT_CRT"
key = "$CERT_KEY"
EOF

sudo mv /tmp/xo-server-config.toml "$CONFIG_DIR/config.toml"
sudo chown "$RUN_USER":"$RUN_USER" "$CONFIG_DIR/config.toml"
sudo chmod 600 "$CONFIG_DIR/config.toml"

# Ensure ownership of repo and config
sudo chown -R "$RUN_USER":"$RUN_USER" "$XO_DIR" "$CONFIG_DIR"

# Create a systemd service to run xo-server as the invoking user
SERVICE_FILE=/etc/systemd/system/xo-server.service
echo "Creating systemd service $SERVICE_FILE"
sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=XO Server
After=network-online.target

[Service]
Environment="DEBUG=xo:main"
Type=simple
User=$RUN_USER
Group=$RUN_USER
WorkingDirectory=$XO_SERVER_DIR
ExecStart=$(command -v node) $XO_SERVER_DIR/dist/cli.mjs
Restart=always
RestartSec=5
SyslogIdentifier=xo-server

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now xo-server

echo "Waiting for xo-server to become active..."
for i in {1..30}; do
	if sudo systemctl is-active --quiet xo-server; then
		# quick HTTP check
		if curl -k --max-time 3 https://127.0.0.1/ >/dev/null 2>&1; then
			echo "Xen Orchestra is up and responding over HTTPS."
			break
		fi
	fi
	sleep 2
	if [ "$i" -eq 30 ]; then
		echo "Timed out waiting for xo-server to start. Check 'systemctl status xo-server' for details." >&2
		exit 1
	fi
done

echo "Installation and service setup complete. Xen Orchestra should be available on ports 80 and 443 (HTTPS)."
echo "Default web UI credentials (if first time) are: admin@admin.net / admin"

exit 0

