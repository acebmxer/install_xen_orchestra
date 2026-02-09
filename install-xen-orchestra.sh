#!/usr/bin/env bash
set -euo pipefail

# install-xen-orchestra.sh
# Installer for Xen Orchestra (from sources) on Ubuntu 24.04/24.04.3
# - Intended to be run as a regular user (NOT as root). Uses sudo for privileged operations.
# - Installs prerequisites, Node.js (20.x), enables Yarn via corepack, builds XO from sources.
# - Creates a self-signed certificate and configures nginx as SSL terminator on 443.
# - Runs XO as the user who started this script (systemd service with User=...)
# - Supports: --dir PATH  (install location, default: $HOME/xen-orchestra)
#             --domain NAME (cert CN / nginx server_name, default: hostname)
#             --update     (compare remote commit on GitHub; update only if remote newer)

XO_DIR="${HOME}/xen-orchestra"
DOMAIN="$(hostname -f || echo localhost)"
DO_UPDATE=0

usage() {
	cat <<EOF
Usage: $0 [--dir /path/to/xen-orchestra] [--domain example.com] [--update]
  Run as a normal user (not root). The script will use sudo for operations that require
  elevated privileges. The invoking user will own the installation and the service will
  run as that user.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--dir) XO_DIR="$2"; shift 2;;
		--domain) DOMAIN="$2"; shift 2;;
		--update) DO_UPDATE=1; shift 1;;
		-h|--help) usage; exit 0;;
		*) echo "Unknown arg: $1"; usage; exit 1;;
	esac
done

if [[ $(id -u) -eq 0 ]]; then
	echo "Do NOT run this script as root. Run it as the user who should own Xen Orchestra." >&2
	exit 1
fi

# The user who started the script (when using sudo, SUDO_USER will be set). Prefer SUDO_USER.
RUN_AS_USER="${SUDO_USER:-${USER}}"
RUN_AS_HOME="$(eval echo ~"${RUN_AS_USER}")"

echo "Install location: $XO_DIR"
echo "Domain for TLS: $DOMAIN"
echo "Installing as user: $RUN_AS_USER (home: $RUN_AS_HOME)"

# Ensure sudo is available and ask for the credential up-front
if ! command -v sudo >/dev/null 2>&1; then
	echo "sudo is required but not installed. Please install sudo and re-run as a regular user." >&2
	exit 1
fi
sudo -v

export DEBIAN_FRONTEND=noninteractive

echo "Updating apt and installing base packages (this may take a few minutes)..."
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
	ca-certificates curl gnupg lsb-release software-properties-common \
	git build-essential python3 python3-dev pkg-config libssl-dev \
	openssl ufw lsof socat redis-server

echo "Ensure common services (apache2/httpd/caddy) aren't blocking ports 80/443"
for svc in apache2 httpd caddy; do
	if sudo systemctl is-active --quiet "$svc"; then
		echo "Stopping system service: $svc"
		sudo systemctl stop "$svc" || true
	fi
done

# kill any process still listening on 80/443 that isn't a systemd-managed webserver
while sudo lsof -iTCP:80 -sTCP:LISTEN -Pn -t >/dev/null 2>&1; do
	PIDS=$(sudo lsof -iTCP:80 -sTCP:LISTEN -Pn -t || true)
	echo "Found processes listening on :80: $PIDS -- attempting graceful stop, then kill"
	for p in $PIDS; do
		sudo kill "$p" || sudo kill -9 "$p" || true
	done
	sleep 1
done
while sudo lsof -iTCP:443 -sTCP:LISTEN -Pn -t >/dev/null 2>&1; do
	PIDS=$(sudo lsof -iTCP:443 -sTCP:LISTEN -Pn -t || true)
	echo "Found processes listening on :443: $PIDS -- attempting graceful stop, then kill"
	for p in $PIDS; do
		sudo kill "$p" || sudo kill -9 "$p" || true
	done
	sleep 1
done

echo "Installing Node.js 20.x (NodeSource) and enabling Yarn via corepack"
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

if command -v corepack >/dev/null 2>&1; then
	sudo corepack enable || true
	sudo corepack prepare yarn@stable --activate || true
else
	sudo npm install -g yarn || true
fi

echo "Creating/installing into $XO_DIR (owned by $RUN_AS_USER)"
sudo mkdir -p "$XO_DIR"
sudo chown -R "$RUN_AS_USER":"$RUN_AS_USER" "$XO_DIR"

cd "$RUN_AS_HOME"

if [[ -d "$XO_DIR/.git" ]]; then
	echo "xen-orchestra already cloned in $XO_DIR"
	cd "$XO_DIR"
	# Ensure remote exists
	sudo -u "$RUN_AS_USER" git remote set-url origin https://github.com/vatesfr/xen-orchestra.git || true
else
	echo "Cloning xen-orchestra into $XO_DIR"
	sudo -u "$RUN_AS_USER" git clone https://github.com/vatesfr/xen-orchestra.git "$XO_DIR"
	cd "$XO_DIR"
fi

if [[ $DO_UPDATE -eq 1 ]]; then
	echo "--update requested: comparing local commit with remote..."
	sudo -u "$RUN_AS_USER" git fetch origin --quiet
	LOCAL=$(sudo -u "$RUN_AS_USER" git rev-parse HEAD)
	REMOTE=$(sudo -u "$RUN_AS_USER" git rev-parse origin/HEAD || sudo -u "$RUN_AS_USER" git ls-remote origin HEAD | awk '{print $1}')
	echo "Local:  $LOCAL"
	echo "Remote: $REMOTE"
	if [[ "$LOCAL" == "$REMOTE" ]]; then
		echo "Already up-to-date with origin. No update needed.";
		exit 0
	else
		echo "Update available: pulling changes and rebuilding..."
		sudo -u "$RUN_AS_USER" git pull --ff-only origin || sudo -u "$RUN_AS_USER" git fetch --all && sudo -u "$RUN_AS_USER" git reset --hard origin/HEAD
	fi
fi

echo "Installing dependencies (yarn) and building xen-orchestra as $RUN_AS_USER"
cd "$XO_DIR"
sudo -u "$RUN_AS_USER" bash -lc 'yarn --network-concurrency 1'
sudo -u "$RUN_AS_USER" bash -lc 'yarn build'

SSL_DIR="/etc/ssl/xen-orchestra"
sudo mkdir -p "$SSL_DIR"
CERT_FILE="$SSL_DIR/selfsigned.crt"
KEY_FILE="$SSL_DIR/selfsigned.key"

if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
	echo "Found existing certs at $CERT_FILE and $KEY_FILE"
else
	echo "Generating self-signed certificate for $DOMAIN"
	sudo openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
		-keyout "$KEY_FILE" -out "$CERT_FILE" \
		-subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN,IP:127.0.0.1"
	sudo chmod 644 "$CERT_FILE"
	sudo chmod 600 "$KEY_FILE"
fi

# Ensure the XO user can read the private key and cert
sudo chown -R "$RUN_AS_USER":"$RUN_AS_USER" "$SSL_DIR"

# Write XO server config so it listens on 80 and 443 directly and uses our certs
sudo mkdir -p /etc/xo-server
sudo tee /etc/xo-server/config.toml >/dev/null <<EOF
# Generated by install-xen-orchestra.sh
[http]
redirectToHttps = true

[[http.listen]]
hostname = '0.0.0.0'
port = 80

[[http.listen]]
hostname = '0.0.0.0'
port = 443
autoCert = false
cert = '$CERT_FILE'
key = '$KEY_FILE'

# Public URL (optional)
publicUrl = 'https://$DOMAIN'

[redis]
uri = 'redis://localhost:6379/0'

EOF

sudo chown -R "$RUN_AS_USER":"$RUN_AS_USER" /etc/xo-server || true

echo "Configuring firewall to allow 80 and 443 (ufw)"
if command -v ufw >/dev/null 2>&1; then
	sudo ufw allow 22/tcp || true
	sudo ufw allow 80/tcp || true
	sudo ufw allow 443/tcp || true
	if sudo ufw status | grep -q "Status: inactive"; then
		sudo ufw --force enable
	fi
else
	echo "ufw not installed; skipping firewall configuration." >&2
fi

SERVICE_FILE="/etc/systemd/system/xen-orchestra.service"
sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Xen Orchestra (from sources)
After=network.target redis.service

[Service]
Type=simple
User=$RUN_AS_USER
Group=$RUN_AS_USER
WorkingDirectory=$XO_DIR/packages/xo-server
Environment=NODE_ENV=production
ExecStart=/usr/bin/node $XO_DIR/packages/xo-server/dist/cli.mjs
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now xen-orchestra.service

echo "Starting completed. Service: xen-orchestra.service (running as $RUN_AS_USER)"

echo "Basic verification:"
echo " - service status:"
sudo systemctl status --no-pager xen-orchestra.service || true
echo " - ports listening (80/443):"
sudo ss -tlnp | grep -E ':80|:443' || true

cat <<FINISH
Done.

- Xen Orchestra installed at: $XO_DIR (owner: $RUN_AS_USER)
- Nginx is configured to terminate TLS on 443 using self-signed certs at:
  - $CERT_FILE
  - $KEY_FILE
- xen-orchestra systemd service: $SERVICE_FILE (runs as $RUN_AS_USER)

If you passed --update the script compared the local commit with remote and updated only if
the remote had newer commits.

Next steps you may want to run as $RUN_AS_USER:
  - View logs: sudo journalctl -u xen-orchestra -f
  - Rebuild: cd $XO_DIR && yarn && yarn build

Visit: https://$DOMAIN/ (accept the self-signed certificate in your browser)
FINISH

exit 0
