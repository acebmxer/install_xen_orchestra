# Xen Orchestra Installation Script

[![CI](https://github.com/acebmxer/install_xen_orchestra/actions/workflows/ci.yml/badge.svg)](https://github.com/acebmxer/install_xen_orchestra/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Automated installation and management of [Xen Orchestra](https://xen-orchestra.com/) from source.

## Available Functions

| Function | CLI Flag | Description |
|----------|----------|-------------|
| Install | `--install` | Fresh install of Xen Orchestra |
| Update | `--update` | Update existing installation (with backup) |
| Restore | `--restore` | Restore from a previous backup |
| Rebuild | `--rebuild` | Fresh clone + clean build, preserves settings |
| Reconfigure | `--reconfigure` | Apply config changes without rebuilding |
| XO Proxy | `--proxy` | Deploy XO Proxy to a Xen pool master |
| Edit Config | *(menu only)* | Open `xo-config.cfg` in your preferred editor |
| Rename Config | *(menu only)* | Rename `sample-xo-config.cfg` to `xo-config.cfg` |

Running without flags launches an interactive menu. All flags also work directly:

```bash
./install-xen-orchestra.sh           # interactive menu
./install-xen-orchestra.sh --update  # run update directly
./install-xen-orchestra.sh --help    # show all options
```

## Interactive Menu

Running the script with no arguments opens a two-column menu with keyboard navigation:

```
  ╔══════════════════════════════════════════════════════════════════════════════════╗
  ║              Install Xen Orchestra from Sources Setup and Update                 ║
  ╚══════════════════════════════════════════════════════════════════════════════════╝

                        Current Script Commit : 693f4 (Branch: main)
                        Master Script Commit  : 693f4 (Branch: main)
                        Current XO Commit     : a1b2c (Branch: master)
                        Master XO Commit      : d4e5f (Branch: master)
                        Current Node          : v24.15.0

  ──────────────────────────────────────────────────────────────────────────────────

  ▸ [✓] Install Xen Orchestra                   [ ] Reconfigure Xen Orchestra
    [ ] Update Xen Orchestra                    [ ] Rebuild Xen Orchestra
    [ ] Rename Sample-xo-config.cfg             [ ] Edit xo-config.cfg
    [ ] Install XO Proxy

  ──────────────────────────────────────────────────────────────────────────────────

  Selected: 1

  ↑↓←→ Navigate   SPACE Select/Deselect   ENTER Confirm   Q Quit
```

Select one or more items with SPACE, then press ENTER to run them.

## Quick Start

```bash
git clone https://github.com/acebmxer/install_xen_orchestra.git
cd install_xen_orchestra
cp sample-xo-config.cfg xo-config.cfg
nano xo-config.cfg   # edit to your liking
./install-xen-orchestra.sh
```

> **Do NOT run with `sudo`.** Run as a normal user with sudo privileges — the script handles `sudo` internally.

If `xo-config.cfg` doesn't exist, it will be created automatically from the sample.

## Configuration

All settings live in `xo-config.cfg`. See [sample-xo-config.cfg](sample-xo-config.cfg) for full documentation of every option.

Key settings:

| Option | Default | Description |
|--------|---------|-------------|
| `HTTP_PORT` | 80 | HTTP port |
| `HTTPS_PORT` | 443 | HTTPS port |
| `INSTALL_DIR` | /opt/xen-orchestra | Installation directory |
| `GIT_BRANCH` | master | Git branch or tag |
| `NODE_VERSION` | 24.15.0 | Node.js version |
| `SERVICE_USER` | xo-service | Service user (set to `root` for VMware V2V import) |
| `BACKUP_KEEP` | 5 | Number of backups to retain |
| `BIND_ADDRESS` | 0.0.0.0 | Bind address |
| `REVERSE_PROXY_TRUST` | false | Trust X-Forwarded headers from proxy IP |

> **Note on `BACKUP_KEEP` rotation:** The retention policy only applies to backups created by the current version of the script. Backups made by older script versions may use a different naming convention and will **not** be counted or pruned by the rotation logic. If you are upgrading from an older version, manually review your backup directory (`BACKUP_DIR` in config, default `/var/lib/xo-backups`) and remove any legacy-named archives you no longer need.

## Default Credentials

After installation, access the web interface at `https://your-server-ip`.

- **Username:** `admin@admin.net`
- **Password:** `admin`

> Change the default password immediately after first login.

## Supported Operating Systems

- Debian 10/11/12/13
- Ubuntu (all supported versions)
- RHEL / CentOS / AlmaLinux / Rocky
- Fedora

## Running Task Detection (Update Safety)

Before applying an update, the script queries the Xen Orchestra REST API for active tasks (e.g. running backups, VM exports). If any are found, the update is aborted to prevent data loss or corruption.

### Authentication

Only **admin-level** XO accounts can access the REST API. Authentication is resolved in priority order:

| Priority | Method | Source |
|----------|--------|--------|
| 1 | Auth token | `XO_TASK_CHECK_TOKEN` in `xo-config.cfg` |
| 2 | Credentials | `XO_TASK_CHECK_USER` / `XO_TASK_CHECK_PASS` in `xo-config.cfg` |
| 3 | Interactive | Prompted at runtime (press Enter to skip) |

### Recommended: Dedicated XO Account

It is recommended to create a **dedicated XO web UI account** solely for the task check (e.g. `task-checker@local.net`). This account:

- Must have **Admin** privileges (required by the REST API)
- Exists only within the XO web interface — no shell access, SSH keys, or OS-level permissions are needed
- Provides a clear audit trail separate from personal accounts
- Prevents shared credentials from being used for unrelated actions

You are free to use any admin account you choose, but a dedicated account is the safest approach.

### Using an Auth Token (Recommended)

Tokens are more secure than storing a password — they can be revoked independently and expire after 30 days by default.

1. Log into the XO web UI with the dedicated account
2. Generate a token:
   ```bash
   curl -X POST -u 'task-checker@local.net:yourpassword' \
     https://localhost/rest/v0/users/me/authentication_tokens -k
   ```
3. Copy the `id` field from the response
4. Add to `xo-config.cfg`:
   ```bash
   XO_TASK_CHECK_TOKEN=UlTBEnFeL12XocK-7Qx-DKvOYbPn0eG7Z2oMvOniNjg
   ```

### Using Credentials

Alternatively, store the account credentials directly:

```bash
XO_TASK_CHECK_USER=task-checker@local.net
XO_TASK_CHECK_PASS=changeme
```

> If neither token nor credentials are configured, the script will prompt interactively during each update.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `XO_DEBUG=1` | Enable debug mode (`set -x`) |
| `XO_NO_SELF_UPDATE=1` | Skip automatic script self-update |

## Troubleshooting

Check service logs:

```bash
sudo journalctl -u xo-server -n 50
```

If the build is broken, rebuild (takes a backup first):

```bash
./install-xen-orchestra.sh --rebuild
```

### Build fails with OOM / out-of-memory error

The Yarn build is memory-intensive. On hosts with less than 2 GB RAM the Node.js process can be killed by the kernel OOM killer mid-build, leaving an incomplete install.

Add or increase swap to give the build room:

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

Re-run the install or `--rebuild` after the swap is active. To make it permanent across reboots, add `/swapfile none swap sw 0 0` to `/etc/fstab`.

### NodeSource GPG key failure (air-gapped / offline hosts)

On hosts without internet access (or with strict egress firewall rules) the NodeSource repository setup script fails because it cannot reach `keyserver.ubuntu.com` or `deb.nodesource.com`.

**Option A** — pre-download and import the key manually, then copy the `.deb`/`.rpm` packages to the host.

**Option B** — set `NODE_VERSION` to a specific patch version (e.g. `24.15.0`) in `xo-config.cfg`. The script will then download a pre-built binary directly from `nodejs.org` instead of using the NodeSource package repository.

### `git` reports "dubious ownership" and exits

Recent versions of Git refuse to operate on a repository owned by a different user than the one running the command. This can happen when `sudo` is used inconsistently or when the install directory was created by `root` but the script is run as a normal user.

Fix it by resetting ownership to match your `SERVICE_USER`:

```bash
sudo chown -R xo-service:xo-service /opt/xen-orchestra
```

Replace `xo-service` with the value of `SERVICE_USER` in `xo-config.cfg`. Re-running the script afterwards will resolve the rest.

### RedHat / Rocky / AlmaLinux: SELinux denials or systemd capability errors

On SELinux-enforcing systems the `xo-server` service may fail to bind ports or access network resources. Check for AVC denials:

```bash
sudo ausearch -m avc -ts recent | grep xo-server
```

If denials are present, generate and apply a local policy module:

```bash
sudo ausearch -m avc -ts recent | audit2allow -M xo-server-local
sudo semodule -i xo-server-local.pp
```

Alternatively, set the service to `permissive` mode while investigating:

```bash
sudo semanage permissive -a xo_server_t
```

`audit2allow` and `semanage` are provided by the `policycoreutils-python-utils` package on RHEL/Rocky/Alma.

## License

This project is licensed under the [MIT License](LICENSE). Xen Orchestra itself is licensed under [AGPL-3.0](https://github.com/vatesfr/xen-orchestra/blob/master/LICENSE).

## Credits

- [Xen Orchestra](https://xen-orchestra.com/) by [Vates](https://vates.tech/)
- [Installation Documentation](https://docs.xen-orchestra.com/installation#from-the-sources)
