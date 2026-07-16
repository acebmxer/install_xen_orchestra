# Xen Orchestra Installation Script

[![CI](https://github.com/acebmxer/install_xen_orchestra/actions/workflows/ci.yml/badge.svg)](https://github.com/acebmxer/install_xen_orchestra/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Automated installation and management of [Xen Orchestra](https://xen-orchestra.com/) from source.

> ## ⚠️ Upgrading from an earlier version of this script? Read this first.
>
> This version bumps the config schema to **v2** (adds `PUBLIC_URL` and
> `ENCRYPT_REDIS_CREDENTIALS`) and corrects two `config.toml` generation bugs.
> Your `xo-config.cfg` is migrated automatically and non-destructively, but the
> corrected `/etc/xo-server/config.toml` is **only written by `--reconfigure`**.
>
> **Run `--reconfigure` once** before resuming normal updates:
>
> ```bash
> ./install-xen-orchestra.sh --reconfigure
> ```
>
> This regenerates `config.toml` with the fixes (your old file is backed up
> first; data in `/var/lib/xo-server` is untouched). It is **strongly
> recommended** if you set both `REDIRECT_TO_HTTPS=true` and
> `REVERSE_PROXY_TRUST` — that combination previously produced a duplicate
> `[http]` section and silently dropped one of the settings.
>
> Afterwards, run `--update` as normal for routine XO updates — `--update` does
> not need to be preceded by `--reconfigure` again.

## Available Functions

| Function | CLI Flag | Description |
|----------|----------|-------------|
| Install | `--install` | Fresh install of Xen Orchestra |
| Update | `--update` | Update existing installation (with backup) |
| Restore | `--restore` | Restore from a previous backup |
| Rebuild | `--rebuild` | Fresh clone + clean build, preserves settings |
| Reconfigure | `--reconfigure` | Apply config changes without rebuilding |
| XO Proxy | `--proxy` | Deploy XO Proxy to a Xen pool master |
| Adjust Memory | `--adjust-memory` | Raise the heap memory allocated to the `xo-server` process |
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

  ▸ [ ] Install Xen Orchestra          [ ] Reconfigure Xen Orchestra (made changes to config)
    [ ] Update Xen Orchestra           [ ] Rebuild Xen Orchestra (wipe & reinstall maintain settings)
    [ ] Rename Sample-xo-config.cfg    [ ] Edit xo-config.cfg
    [ ] Install XO Proxy               [ ] Restore Backup
                       [ ] Adjust Xen Orchestra Memory Allocation

  ──────────────────────────────────────────────────────────────────────────────────

  Selected: 0

  ↑↓←→ Navigate   SPACE Select/Deselect   ENTER Confirm   Q Quit
  Legend: [✓] selected   [ ] not selected
```

Select one or more items with SPACE, then press ENTER to run them.

### Adjust Xen Orchestra Memory Allocation

If `xo-server` runs out of memory you will see a `JavaScript heap out of
memory` fatal error in `journalctl -u xo-server.service`. Raising the VM's RAM
alone does **not** fix this — the systemd service must also pass
`--max-old-space-size` to Node so V8 can use the extra heap.

This option detects the system RAM, suggests a heap size (total RAM minus
~512 MB reserved for the OS), backs up `/etc/systemd/system/xo-server.service`,
rewrites the `ExecStart` line, then reloads systemd and restarts `xo-server`.

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
| `NODE_VERSION` | 24 | Node.js version (latest LTS; use e.g. `24.15.0` to pin a patch) |
| `SERVICE_USER` | xo-service | Service user; non-root recommended (set to `root` for VMware V2V import — see encryption note for credential-encryption behavior) |
| `BACKUP_KEEP` | 5 | Number of backups to retain |
| `BIND_ADDRESS` | 0.0.0.0 | Bind address |
| `REVERSE_PROXY_TRUST` | false | Trust X-Forwarded headers from proxy IP |
| `PUBLIC_URL` | *(unset)* | Public URL advertised to external entities (e.g. XO Lite) |
| `ENCRYPT_REDIS_CREDENTIALS` | false | Encrypt Redis credentials at rest — XCP-ng guests only (see note below) |

> **Note on `BACKUP_KEEP` rotation:** The retention policy only applies to backups created by the current version of the script. Backups made by older script versions may use a different naming convention and will **not** be counted or pruned by the rotation logic. If you are upgrading from an older version, manually review your backup directory (`BACKUP_DIR` in config, default `/var/lib/xo-backups`) and remove any legacy-named archives you no longer need.

> **Note on `ENCRYPT_REDIS_CREDENTIALS`:** This is an opt-in xo-server feature that encrypts credentials stored in Redis at rest (AES-256-GCM). It **only works when Xen Orchestra runs as a VM on a XenServer/XCP-ng host**, because half of the encryption key is stored in XenStore. It will **not** work on bare metal or on other hypervisors (KVM, VMware, Hyper-V). Leave it `false` unless XO is an XCP-ng guest.
>
> **Works with either `SERVICE_USER`:** root reaches XenStore directly. For a **non-root** `SERVICE_USER`, the xenbus device is root-only by default, so the installer adds the user to a `xenstore` group and installs a udev rule (`/etc/udev/rules.d/40-xen-xenbus-xo.rules`) granting access — without this, xo-server cannot derive the key and rejects logins (degraded mode). Group membership applies on the next service restart; verify with `sudo -u <SERVICE_USER> xenstore-ls vm-data`.
>
> To opt out later, set it back to `false` and run `--reconfigure` — xo-server decrypts the records and removes the key files automatically.

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

> **Firewall:** On Fedora and RHEL-family systems (which enable `firewalld` by
> default and block inbound HTTP/HTTPS), the installer opens the configured
> `HTTP_PORT`/`HTTPS_PORT` automatically. Debian/Ubuntu ship no active firewall,
> so nothing is changed there. If `firewalld` is not running, the step is
> skipped — open the ports yourself if you add one later.

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

> [!IMPORTANT]
> **Tokens must have a description or they will be deleted during updates.**
>
> During an update the installer flushes stale session tokens from Redis to prevent schema-mismatch 401 errors after XO restarts. It tells session tokens apart from API tokens by checking for a non-empty `description` field in the token's stored JSON:
>
> - Tokens **with** a description → treated as API/integration tokens → **kept**
> - Tokens **without** a description → treated as browser session tokens → **deleted**
>
> This applies to `XO_TASK_CHECK_TOKEN` and to **any other API tokens** used by third-party tools (monitoring agents, Terraform, scripts, etc.) that connect to this XO server. Always create tokens with a meaningful description.

**Option 1 — XO web UI (always prompts for a description):**

1. Log into the XO web UI with the dedicated account
2. Go to **Settings → Authentication tokens → New token**
3. Enter a description (e.g. `installer-task-check`) and copy the generated token value
4. Add to `xo-config.cfg`:
   ```bash
   XO_TASK_CHECK_TOKEN=UlTBEnFeL12XocK-7Qx-DKvOYbPn0eG7Z2oMvOniNjg
   ```

**Option 2 — curl (include a description in the request body):**

1. Log into the XO web UI with the dedicated account
2. Generate a token with a description:
   ```bash
   curl -X POST -u 'task-checker@local.net:yourpassword' \
     https://localhost/rest/v0/users/me/authentication_tokens \
     -H 'Content-Type: application/json' \
     -d '{"description":"installer-task-check"}' -k
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
