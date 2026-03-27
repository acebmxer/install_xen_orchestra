# Xen Orchestra Installation Script

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

                        Current Script Commit : 693f4
                        Master Script Commit  : 693f4
                        Current XO Commit     : a1b2c
                        Master XO Commit      : d4e5f
                        Current Node          : v22.15.0

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
| `NODE_VERSION` | 22 | Node.js version (must be 22 or lower; higher versions are not compatible with Yarn Classic v1) |
| `SERVICE_USER` | xo-service | Service user (set to `root` for VMware V2V import) |
| `BACKUP_KEEP` | 5 | Number of backups to retain |
| `BIND_ADDRESS` | 0.0.0.0 | Bind address |
| `REVERSE_PROXY_TRUST` | false | Trust X-Forwarded headers from proxy IP |

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

## License

This installation script is provided as-is. Xen Orchestra itself is licensed under [AGPL-3.0](https://github.com/vatesfr/xen-orchestra/blob/master/LICENSE).

## Credits

- [Xen Orchestra](https://xen-orchestra.com/) by [Vates](https://vates.tech/)
- [Installation Documentation](https://docs.xen-orchestra.com/installation#from-the-sources)
