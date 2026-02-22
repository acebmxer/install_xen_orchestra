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
- Interactive restore from any available backup
- Rebuild functionality — fresh clone + clean build on the current branch, preserves settings
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

The easiest fix is to use the built-in rebuild command, which takes a backup first:

```bash
./install-xen-orchestra.sh --rebuild
```

Or manually:

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
