#!/usr/bin/env bash
set -euo pipefail

# simulate-install.sh
# Simple, non-destructive simulator for install-xen-orchestra.sh
# It will inspect the installer and print the major actions it would perform

SCRIPT="install-xen-orchestra.sh"
if [[ ! -f "$SCRIPT" ]]; then
  echo "Installer not found: $SCRIPT" >&2
  exit 1
fi

echo "Simulator: parsing $SCRIPT and printing planned actions (no changes made)"
echo

# Print header info: detected defaults
grep -E "^XO_DIR=|^DOMAIN=|^DO_UPDATE=" -n "$SCRIPT" || true

# Commands of interest patterns
patterns=(
  "apt-get install"
  "curl -fsSL"
  "git clone"
  "git pull"
  "yarn build"
  "yarn --network-concurrency"
  "openssl req"
  "systemctl enable --now"
  "systemctl enable"
  "systemctl daemon-reload"
  "ufw allow"
  "lsof -iTCP"
  "ss -tlnp"
)

# Scan script and print matching lines with context
for p in "${patterns[@]}"; do
  echo "--- Matches for: $p"
  grep -n "${p}" "$SCRIPT" || echo "(none)"
  echo
done

# Print final actions summary
cat <<EOF
Summary (simulated):
- Update apt and install base packages (Node.js via NodeSource, build tools, redis, ufw, etc.)
- Ensure common services (apache2/httpd/caddy) stopped if active
- Free ports 80 and 443 if currently listened on (kill processes)
- Install Node.js 20.x and enable Yarn (corepack)
- Clone or update https://github.com/vatesfr/xen-orchestra into chosen directory
- Run 'yarn' and 'yarn build' as the invoking user
- Generate a self-signed certificate under /etc/ssl/xen-orchestra if missing
- Write /etc/xo-server/config.toml pointing to the cert and key
- Configure UFW to allow 80 and 443
- Create /etc/systemd/system/xen-orchestra.service and enable/start it

This is a non-destructive simulation. To perform the real install, run:
  bash install-xen-orchestra.sh --domain your.domain.tld
EOF
