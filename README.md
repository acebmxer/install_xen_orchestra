# Xen Orchestra Installation Script

Automated installation script for [Xen Orchestra](https://xen-orchestra.com/) from source, based on the [official documentation](https://docs.xen-orchestra.com/installation#from-the-sources).

## Features

- Installs all required dependencies and prerequisites automatically
- Uses Node.js 20 LTS (with npm v10)
- Yarn package manager installed globally
- Self-signed SSL certificate generation for HTTPS
- Direct port binding (80 and 443) - no proxy required
- Systemd service for automatic startup
- Update functionality with commit comparison
- Automatic backups before updates (keeps last 5)
- Interactive restore from any available backup
- Rebuild functionality — fresh clone + clean build on the current branch, preserves settings
- Reconfigure functionality — apply configuration changes without rebuilding
- Configurable via simple config file
- **Customizable service user** - run as any username or root, defaults to 'xo'
- **Automatic swap space management** - creates 2GB swap if needed for builds
- **NFS mount support** - automatically configures sudo permissions for remote storage
- **Memory-efficient builds** - prevents out-of-memory errors on low-RAM systems

## Quick Start

### 1. Clone this repository

```bash
git clone https://github.com/acebmxer/install_xen_orchestra.git
cd install_xen_orchestra
```

### 2. Configure the installation

Copy the sample configuration file and customize it:

```bash
cp sample-xo-config.cfg xo-config.cfg
```

Edit `xo-config.cfg` with your preferred settings:

```bash
nano xo-config.cfg
```

> **Note:** If `xo-config.cfg` is not found when running the script, it will automatically be created from `sample-xo-config.cfg` with default settings.

### 3. Run the installation

**Important:** Do NOT run this script with `sudo`. Run as a normal user with sudo privileges - the script will use `sudo` internally for commands that require elevated permissions.

```bash
./install-xen-orchestra.sh
```

## Configuration Options

The `xo-config.cfg` file supports the following options:

| Option | Default | Description |
|--------|---------|-------------|
| `HTTP_PORT` | 80 | HTTP port for web interface |
| `HTTPS_PORT` | 443 | HTTPS port for web interface |
| `INSTALL_DIR` | /opt/xen-orchestra | Installation directory |
| `SSL_CERT_DIR` | /etc/ssl/xo | SSL certificate directory |
| `SSL_CERT_FILE` | xo-cert.pem | SSL certificate filename |
| `SSL_KEY_FILE` | xo-key.pem | SSL private key filename |
| `GIT_BRANCH` | master | Git branch (master, stable, or tag) |
| `BACKUP_DIR` | /opt/xo-backups | Backup directory for updates |
| `BACKUP_KEEP` | 5 | Number of backups to retain |
| `NODE_VERSION` | 20 | Node.js major version |
| `SERVICE_USER` | xo | Service user (any username, leave empty for root) |
| `DEBUG_MODE` | false | Enable debug logging |
| `BIND_ADDRESS` | 0.0.0.0 | Bind address (0.0.0.0 for all, 127.0.0.1 for localhost) |
| `REDIRECT_TO_HTTPS` | false | Redirect HTTP to HTTPS |
| `REVERSE_PROXY_TRUST` | false | Trust X-Forwarded headers (false, true, or IP list) |
| `REDIS_URI` | - | Redis connection URI (optional) |
| `REDIS_SOCKET` | - | Redis Unix socket path (optional) |

## Updating Xen Orchestra

To update an existing installation:

```bash
./install-xen-orchestra.sh --update
```

The update process will:

1. Compare the installed commit with the latest from GitHub
2. Skip if already up to date
3. Create a backup of the current installation
4. Pull the latest changes
5. Rebuild Xen Orchestra
6. Restart the service

### Backup Management

- Backups are stored in `BACKUP_DIR` (default: `/opt/xo-backups`)
- Only the last `BACKUP_KEEP` backups are retained (default: 5)
- Older backups are automatically purged before each new backup is created
- Backup folder names are timestamped in UTC; dates and times are displayed converted to the local system timezone
- When restoring, backups are listed **newest first** — `[1]` is the most recent, `[5]` is the oldest

## Restoring from Backup

To restore a previous installation:

```bash
./install-xen-orchestra.sh --restore
```

The restore process will:

1. List all available backups **newest first** (1 = newest, 5 = oldest) with their dates and commit hashes
2. Prompt you to select which backup to restore
3. Ask for confirmation before making any changes
4. Stop the running service
5. Replace the current installation with the selected backup
6. Rebuild Xen Orchestra (node_modules are excluded from backups to save space)
7. Restart the service and report the restored commit hash

Example output:

```
==============================================
  Available Backups
==============================================

  [1] xo-backup-20260221_233000  (2026-02-21 06:30:00 PM EST)  commit: a1b2c3d4e5f6 (newest)
  [2] xo-backup-20260221_141500  (2026-02-21 09:15:00 AM EST)  commit: 9f8e7d6c5b4a
  [3] xo-backup-20260220_162000  (2026-02-20 11:20:00 AM EST)  commit: 1a2b3c4d5e6f
  [4] xo-backup-20260219_225200  (2026-02-19 05:52:00 PM EST)  commit: 3c4d5e6f7a8b
  [5] xo-backup-20260219_133000  (2026-02-19 08:30:00 AM EST)  commit: 7d8e9f0a1b2c (oldest)

Enter the number of the backup to restore [1-5], or 'q' to quit:
```

After a successful restore the confirmed commit is displayed:

```
[SUCCESS] Restore completed successfully!
[INFO]    Restored commit: a1b2c3d4e5f6
```

## Rebuilding Xen Orchestra

If your installation becomes corrupted or broken, use `--rebuild` to do a fresh clone and clean build of your current branch **without losing any settings**:

```bash
./install-xen-orchestra.sh --rebuild
```

The rebuild process will:

1. Detect the currently installed branch
2. Display a summary and ask for confirmation
3. Stop the running service
4. Create a backup of the current installation (same as `--update` — saved to `BACKUP_DIR`)
5. Remove the current `INSTALL_DIR` and do a fresh `git clone` of the same branch
6. Perform a clean build (turbo cache cleared)
7. Restart the service and report the new commit hash

> **Note:** Settings stored in `/etc/xo-server` (config.toml) and `/var/lib/xo-server` (databases and state) are **not touched** during a rebuild, so all your connections, users, and configuration are preserved.

## Reconfiguring Xen Orchestra

If you need to change configuration settings (ports, SSL paths, service user, reverse proxy settings, etc.) without rebuilding the entire application, use `--reconfigure`:

```bash
./install-xen-orchestra.sh --reconfigure
```

The reconfigure process will:

1. Display all current configuration from `xo-config.cfg` and ask for confirmation
2. Stop the running service
3. Create a timestamped backup of the current `/etc/xo-server/config.toml`
4. Regenerate `/etc/xo-server/config.toml` from your `xo-config.cfg`
5. Regenerate the systemd service file
6. Restart the service with the new configuration

### Common Use Cases

**Changing Ports:**
```bash
# Edit xo-config.cfg to change HTTP_PORT from 8080 back to 80
nano xo-config.cfg

# Apply the changes
./install-xen-orchestra.sh --reconfigure
```

**Setting up a Reverse Proxy:**
```bash
# Edit xo-config.cfg to configure reverse proxy settings
# - Change HTTP_PORT to 8080
# - Set BIND_ADDRESS to 127.0.0.1
# - Set REVERSE_PROXY_TRUST to your proxy IP
nano xo-config.cfg

# Apply the changes
./install-xen-orchestra.sh --reconfigure
```

**Switching Service User:**
```bash
# Edit xo-config.cfg to change SERVICE_USER
nano xo-config.cfg

# Apply the changes
./install-xen-orchestra.sh --reconfigure
```

> **Note:** Reconfigure regenerates configuration files from `xo-config.cfg`. Your database and user data in `/var/lib/xo-server` are never modified. Config backups are saved to `/etc/xo-server/config.toml.backup-<timestamp>`.

## Service Management

After installation, Xen Orchestra runs as a systemd service:

```bash
# Start the service
sudo systemctl start xo-server

# Stop the service
sudo systemctl stop xo-server

# Check status
sudo systemctl status xo-server

# View logs
sudo journalctl -u xo-server -f
```

## Accessing Xen Orchestra

After installation, access the web interface:

- **HTTP:** `http://your-server-ip`
- **HTTPS:** `https://your-server-ip`

> **Note:** If you changed `HTTP_PORT` or `HTTPS_PORT` in `xo-config.cfg` from the defaults (80/443), append the port to the URL — e.g. `http://your-server-ip:8080`

### Default Credentials

- **Username:** `admin@admin.net`
- **Password:** `admin`

> **Warning:** Change the default password immediately after first login!

## Switching Branches

To switch to a different branch (e.g., from `master` to `stable`):

1. Edit `xo-config.cfg` and change `GIT_BRANCH`
2. Run the update:

```bash
./install-xen-orchestra.sh --update
```

The script will automatically fetch and checkout the new branch during the update process.

## Reverse Proxy Setup

If you want to use an external reverse proxy (nginx, Apache, Caddy, etc.) instead of exposing Xen Orchestra directly:

### 1. Configure XO for Reverse Proxy

Edit `xo-config.cfg` with these settings:

```bash
# Use non-privileged ports
HTTP_PORT=8080
HTTPS_PORT=8443

# Bind to localhost only if proxy is on same host
# (or 0.0.0.0 if proxy is on different host)
BIND_ADDRESS=127.0.0.1

# Trust X-Forwarded-* headers from your proxy
# Replace with your proxy's IP address
REVERSE_PROXY_TRUST=127.0.0.1

# Optional: Let XO redirect HTTP to HTTPS
# (or handle this in your reverse proxy)
REDIRECT_TO_HTTPS=false
```

### 2. Configure Your Reverse Proxy

#### Nginx Example

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name xo.example.com;

    # SSL configuration
    ssl_certificate /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;

    # Redirect HTTP to HTTPS
    if ($scheme = http) {
        return 301 https://$server_name$request_uri;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_read_timeout 1800;

        # Large file uploads
        client_max_body_size 4G;
    }
}
```

#### Apache Example

```apache
<VirtualHost *:80>
    ServerName xo.example.com
    Redirect permanent / https://xo.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName xo.example.com

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/your-cert.pem
    SSLCertificateKeyFile /etc/ssl/private/your-key.pem

    # Enable required modules: mod_proxy, mod_proxy_http, mod_proxy_wstunnel, mod_rewrite
    
    # WebSocket support
    RewriteEngine On
    RewriteCond %{HTTP:upgrade} websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:8080/$1 [L,P]

    # HTTP proxy
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
    
    # Forward headers
    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>
```

#### Caddy Example

```caddy
xo.example.com {
    reverse_proxy localhost:8080
}
```

### 3. Install or Update XO

Run the installation or update script as usual:

```bash
./install-xen-orchestra.sh
```

### Benefits of Using a Reverse Proxy

- **Centralized SSL/TLS management** - Use Let's Encrypt or your own certificates
- **Multiple services on same IP** - Host multiple web apps on ports 80/443
- **Advanced features** - Load balancing, caching, rate limiting, WAF
- **Better logging** - Centralized access logs and monitoring
- **Security** - Additional layer between internet and XO server

## System Requirements

### Minimum Hardware

- **RAM:** 2GB minimum (4GB+ recommended for building)
- **Disk:** 10GB free space
- **CPU:** 1 core minimum (2+ recommended)

> **Note:** The script automatically creates 2GB swap space if insufficient memory is detected during builds to prevent out-of-memory errors.

### Dependencies

The script automatically installs all required dependencies:

**Debian/Ubuntu:**
- apt-transport-https, ca-certificates, libcap2-bin, curl, gnupg
- build-essential, git, patch, sudo
- Node.js v20 (with npm v10), yarn
- redis-server
- python3-minimal, libpng-dev
- lvm2, cifs-utils, nfs-common, ntfs-3g
- libvhdi-utils, dmidecode
- libfuse2t64 (or libfuse2 on older systems)
- software-properties-common (Ubuntu only)

**RHEL/CentOS/Fedora:**
- redis or valkey (RHEL 10+)
- Node.js v20 (with npm v10), yarn
- ca-certificates, gnupg2, curl
- make, automake, gcc, gcc-c++, patch, sudo
- git, libpng-devel
- lvm2, cifs-utils, nfs-utils, ntfs-3g
- dmidecode, libcap, fuse-libs

## Supported Operating Systems

- **Debian 10/11/12/13** (apt-based)
- **Ubuntu** (apt-based, all supported versions)
- **RHEL/CentOS/AlmaLinux/Rocky** (dnf/yum-based)
- **Fedora** (dnf-based)

## Troubleshooting

### Service fails to start

Check the service logs:

```bash
sudo journalctl -u xo-server -n 50
```

### Port binding issues

If running as non-root, the service uses `CAP_NET_BIND_SERVICE` to bind to privileged ports. Ensure systemd is configured correctly.

### Build failures

The easiest fix is to use the built-in rebuild command, which takes a backup first:

```bash
./install-xen-orchestra.sh --rebuild
```

Or manually (if running as non-root SERVICE_USER):

```bash
cd /opt/xen-orchestra
rm -rf node_modules
# Replace 'xo' with your SERVICE_USER if different
sudo -u xo yarn
sudo -u xo yarn build
```

### Out of Memory (OOM) during build

If the build process fails with exit code 137 (killed), your system ran out of memory:

**The script automatically handles this** by:
- Detecting available swap space before building
- Creating 2GB swap file if insufficient
- Setting Node.js memory limits (4GB max)

To manually check/add swap:

```bash
# Check current swap
free -h

# Create 2GB swap file if needed
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### NFS mount errors ("user" NFS mounts not supported)

If you get an error when adding NFS remote storage:
```
mount.nfs: not installed setuid - "user" NFS mounts not supported
```

**The script automatically handles this** by configuring sudo permissions for your service user (default: `xo`) to run mount/umount commands including NFS-specific helpers.

If you encounter this issue on an existing installation:

```bash
# Update sudoers configuration (replace 'xo' with your SERVICE_USER if different)
sudo tee /etc/sudoers.d/xo-server-xo > /dev/null << 'EOF'
# Allow xo-server user to mount/unmount without password
Defaults:xo !requiretty
xo ALL=(ALL:ALL) NOPASSWD:SETENV: /bin/mount, /usr/bin/mount, /bin/umount, /usr/bin/umount, /bin/findmnt, /usr/bin/findmnt, /sbin/mount.nfs, /usr/sbin/mount.nfs, /sbin/mount.nfs4, /usr/sbin/mount.nfs4, /sbin/umount.nfs, /usr/sbin/umount.nfs, /sbin/umount.nfs4, /usr/sbin/umount.nfs4
EOF

sudo chmod 440 /etc/sudoers.d/xo-server-xo
sudo systemctl restart xo-server
```

### NFS permission denied errors

If NFS mounts succeed but you get permission errors when writing:
```
EACCES: permission denied, open '/run/xo-server/mounts/.keeper_*'
```

This is a UID/GID mismatch between the xo-server user and your NFS export permissions:

**Option 1: Run as root** (recommended for simplicity)
```bash
# Edit config
nano xo-config.cfg
# Set: SERVICE_USER=
# (leave empty to run as root)

# Update service (replace 'xo' with your SERVICE_USER if different)
sudo sed -i 's/User=xo/User=root/' /etc/systemd/system/xo-server.service
sudo chown -R root:root /opt/xen-orchestra /var/lib/xo-server /etc/xo-server
sudo systemctl daemon-reload
sudo systemctl restart xo-server
```

**Option 2: Configure NFS for your service user's UID**
On your NFS server, adjust exports to allow your service user's UID (check with `id <username>`), or use appropriate squash settings in your NFS export configuration.

### Redis connection issues

Ensure Redis is running:

```bash
redis-cli ping
# Should respond with: PONG
```

## Security Considerations

- **No Root:** The script refuses to run as root/sudo and uses sudo internally
- **Service User:** Runs as dedicated `xo` user by default (customizable to any username; leave empty for root)
- **SSL:** Self-signed certificate generated automatically for HTTPS
- **Sudo Permissions:** Service user configured with minimal sudo access for:
  - NFS/CIFS mount operations (`/bin/mount`, `/usr/bin/mount`, `/sbin/mount.nfs`, etc.)
  - Unmount operations (`/bin/umount`, `/usr/bin/umount`, `/sbin/umount.nfs`, etc.)
  - Mount point discovery (`/bin/findmnt`, `/usr/bin/findmnt`)
  - All configured in `/etc/sudoers.d/xo-server-<username>` with NOPASSWD for specific commands only
- **Automatic Swap:** Swap file created with secure permissions (600) if needed for builds

## License

This installation script is provided as-is. Xen Orchestra itself is licensed under [AGPL-3.0](https://github.com/vatesfr/xen-orchestra/blob/master/LICENSE).

## Credits

- [Xen Orchestra](https://xen-orchestra.com/) by [Vates](https://vates.tech/)
- [Installation Documentation](https://docs.xen-orchestra.com/installation#from-the-sources)
