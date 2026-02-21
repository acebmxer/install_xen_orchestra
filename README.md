# Xen Orchestra Installation Script

Automated installation script for [Xen Orchestra](https://xen-orchestra.com/) from source, based on the [official documentation](https://docs.xen-orchestra.com/installation#from-the-sources).

## Features

- Installs all required dependencies and prerequisites
- Uses Node.js 20 LTS
- Self-signed SSL certificate generation for HTTPS
- Direct port binding (80 and 443) - no proxy required
- Systemd service for automatic startup
- Update functionality with commit comparison
- Automatic backups before updates (keeps last 5)
- Configurable via simple config file

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
| `SERVICE_USER` | xo | Service user (set empty for root) |
| `DEBUG_MODE` | false | Enable debug logging |

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
- Older backups are automatically purged

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

- **HTTP:** `http://your-server-ip:80`
- **HTTPS:** `https://your-server-ip:443`

### Default Credentials

- **Username:** `admin@admin.net`
- **Password:** `admin`

> **Warning:** Change the default password immediately after first login!

## Switching Branches

To switch to a different branch (e.g., from `master` to `stable`):

1. Edit `xo-config.cfg` and change `GIT_BRANCH`
2. Manually update the repository:

```bash
cd /opt/xen-orchestra
sudo -u xo git fetch origin
sudo -u xo git checkout stable
./install-xen-orchestra.sh --update
```

## Supported Operating Systems

- **Debian/Ubuntu** (apt-based)
- **RHEL/CentOS/AlmaLinux/Rocky** (dnf/yum-based)

## Troubleshooting

### Service fails to start

Check the service logs:

```bash
sudo journalctl -u xo-server -n 50
```

### Port binding issues

If running as non-root, the service uses `CAP_NET_BIND_SERVICE` to bind to privileged ports. Ensure systemd is configured correctly.

### Build failures

Try cleaning and rebuilding:

```bash
cd /opt/xen-orchestra
rm -rf node_modules
sudo -u xo yarn
sudo -u xo yarn build
```

### Redis connection issues

Ensure Redis is running:

```bash
redis-cli ping
# Should respond with: PONG
```

## Security Considerations

- **No Root:** The script refuses to run as root/sudo and uses sudo internally
- **Service User:** Runs as dedicated `xo` user by default
- **SSL:** Self-signed certificate generated automatically
- **Sudo:** Configured only for NFS mount operations

## License

This installation script is provided as-is. Xen Orchestra itself is licensed under [AGPL-3.0](https://github.com/vatesfr/xen-orchestra/blob/master/LICENSE).

## Credits

- [Xen Orchestra](https://xen-orchestra.com/) by [Vates](https://vates.tech/)
- [Installation Documentation](https://docs.xen-orchestra.com/installation#from-the-sources)
