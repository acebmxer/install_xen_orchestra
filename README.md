# Xen Orchestra Installation Script

[![CI](https://github.com/acebmxer/install_xen_orchestra/actions/workflows/ci.yml/badge.svg)](https://github.com/acebmxer/install_xen_orchestra/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/github/v/tag/acebmxer/install_xen_orchestra?label=version&sort=semver&color=brightgreen)](CHANGELOG.md)
[![Last commit](https://img.shields.io/github/last-commit/acebmxer/install_xen_orchestra)](https://github.com/acebmxer/install_xen_orchestra/commits)
[![Issues](https://img.shields.io/github/issues/acebmxer/install_xen_orchestra)](https://github.com/acebmxer/install_xen_orchestra/issues)
[![Stars](https://img.shields.io/github/stars/acebmxer/install_xen_orchestra)](https://github.com/acebmxer/install_xen_orchestra/stargazers)
[![Forks](https://img.shields.io/github/forks/acebmxer/install_xen_orchestra)](https://github.com/acebmxer/install_xen_orchestra/forks)
[![Unique cloners](https://img.shields.io/badge/unique%20cloners-65-brightgreen)](https://github.com/acebmxer/install_xen_orchestra/graphs/traffic)
[![Shell: Bash](https://img.shields.io/badge/shell-bash-4EAA25?logo=gnubash&logoColor=white)](install-xen-orchestra.sh)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-333333?logo=linux&logoColor=white)](#supported-operating-systems)
[![Tests](https://img.shields.io/badge/tests-335%20unit-informational)](https://github.com/acebmxer/install_xen_orchestra/actions/workflows/ci.yml)
[![Distros tested](https://img.shields.io/badge/distros%20tested-10-informational)](#supported-operating-systems)
[![ShellCheck](https://img.shields.io/badge/shellcheck-clean-brightgreen)](https://github.com/acebmxer/install_xen_orchestra/actions/workflows/ci.yml)

Automated installation and management of [Xen
Orchestra](https://xen-orchestra.com/) from source.

> [!IMPORTANT]
> **⚠️ Upgrading from an earlier version of this script? Read this first.**
>
> **This script edits your `xo-config.cfg` by itself.** On the first run after
> an upgrade, it appends any config keys added since your file was written and
> rewrites the `CONFIG_VERSION=` line. It does this without asking, it takes no
> backup, and there is no flag to skip it. It runs on any command that reads
> the config — `--install`, `--update`, `--reconfigure` and `--build-templates`
> included.
>
> It is additive: new keys are appended commented-out with their explanations,
> keys you already have are left alone, and nothing you configured changes
> behaviour. Once your file is at the current schema version the migration
> returns immediately and never writes again — so this is a one-off per
> upgrade, not something that happens every run.
>
> The current schema is **v4**. Depending on how old your file is, it may gain:
>
> | Schema | Keys appended |
> | --- | --- |
> | v2 | `PUBLIC_URL`, `ENCRYPT_REDIS_CREDENTIALS` |
> | v3 | `SSL_CERT_DAYS` |
> | v4 | `TEMPLATE_BUILD_METHOD`, `XO_URL`, `XO_API_TOKEN` |
>
> No key is ever renamed or removed. `XO_TASK_CHECK_TOKEN` in particular keeps
> working — it is read whenever `XO_API_TOKEN` is unset — so a config written
> before the template builder existed needs no edit.
>
> **If you are coming from a schema older than v2**, this version also corrects
> two `config.toml` generation bugs. Your `xo-config.cfg` is migrated
> automatically, but the corrected `/etc/xo-server/config.toml` is **only
> written by `--reconfigure`**.
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

## Read next

| Topic | Page |
| --- | --- |
| Building the VM for you (`--deploy`) | [docs/deployment.md](docs/deployment.md) |
| Building cloud-init VM templates (`--build-templates`) | [docs/templates.md](docs/templates.md) |
| Every config option, and the environment variables | [docs/configuration.md](docs/configuration.md) |
| Update-safety task detection and REST API auth | [docs/authentication.md](docs/authentication.md) |
| Something went wrong | [docs/troubleshooting.md](docs/troubleshooting.md) |
| Code style, tests, releases | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Available Functions

| Function | CLI Flag | Description |
|----------|----------|-------------|
| Deploy | `--deploy` | Create a Debian VM on a XenServer/XCP-ng pool and install XO into it |
| Build Templates | `--build-templates` | Build cloud-init VM templates on a XenServer/XCP-ng pool |
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
  ╔═══════════════════════════════════════════════════════════════════════════════════╗
  ║                Install Xen Orchestra from Sources Setup and Update                ║
  ╚═══════════════════════════════════════════════════════════════════════════════════╝

                  Current Script Commit : 693f4 (Branch: main)
                  Master Script Commit  : 693f4 (Branch: main)
                  Current XO Commit     : a1b2c (Branch: master)
                ⚠ Master XO Commit      : d4e5f (Branch: master) - 12 behind
                  Current Node          : v24.15.0

  ─────────────────────────────────────────────────────────────────────────────────────

  ▸ [ ] Install Xen Orchestra                   [ ] Reconfigure XO (config changed)
    [ ] Update Xen Orchestra                    [ ] Rebuild XO (wipe, keep settings)
    [ ] Rename Sample-xo-config.cfg             [ ] Edit xo-config.cfg
    [ ] Install XO Proxy                        [ ] Restore Backup
    [ ] Deploy XO to a new VM (creates VM)      [ ] Adjust XO Memory Allocation
    [ ] VM Template Library

  ─────────────────────────────────────────────────────────────────────────────────────

  Selected: 0

  ↑↓←→ Navigate   SPACE Select/Deselect   ENTER Confirm   Q Quit
  Legend: [✓] selected   [ ] not selected
```

Select one or more items with SPACE, then press ENTER to run them.

When the installed commit differs from XO's master, the `Master XO Commit` line
is highlighted and shows how many commits the installation is behind.

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

> [!WARNING]
> **Do NOT run with `sudo`.** Run as a normal user with sudo privileges — the
> script handles `sudo` internally.

If `xo-config.cfg` doesn't exist, it will be created automatically from the sample.

## Deploying to a New VM (`--deploy`)

No Linux VM to install into? `--deploy` builds one for you — it creates a
Debian 13 VM on a XenServer/XCP-ng pool, installs Xen Orchestra into it, and
hands back the address. Run it from your own workstation:

```bash
./install-xen-orchestra.sh --deploy
```

It asks for your pool master, a storage repository, a network, and a **static
IP** (required — a stock cloud image cannot report a DHCP lease back), then
does the rest unattended. The VM it creates is tagged `xo-deployed` and stamped
with `other-config` keys recording that this script deployed it, which version,
and when — so an appliance can be identified as the script's work later, and
filtered for by tag in XO's VM list. The full walkthrough —
requirements, the admin account and SSH key handling, image verification, what
it hardens on the way out, reading the deployment stamp back, and the pre-flight
probe — is in [docs/deployment.md](docs/deployment.md).

## Building VM Templates (`--build-templates`)

Xen Orchestra's Hub does not work on an install from sources — the `cloud.*`
API behind it has no open-source implementation, so there is nothing to
unlock. `--build-templates` builds the equivalent on your pool instead, from
each distribution's own published cloud image:

```bash
./install-xen-orchestra.sh --build-templates
```

The library lists every distribution in the catalog, with the login the built
template uses:

```
  VM Template Library

  Cloud-init templates built from each distribution's own published
  image. Once built they appear in Xen Orchestra under New -> VM.

      AlmaLinux 8  Coming Soon...
      AlmaLinux 9  Coming Soon...
      AlmaLinux 10  Coming Soon...
      CentOS Stream 9  Coming Soon...
      CentOS Stream 10  Coming Soon...
  ▸ [ ] Debian 12 (Bookworm) (login: debian)
    [ ] Debian 13 (Trixie) (login: debian)
      Fedora 43  Coming Soon...
      Fedora 44  Coming Soon...
      Rocky Linux 8  Coming Soon...
      Rocky Linux 9  Coming Soon...
      Rocky Linux 10  Coming Soon...
    [ ] Ubuntu 22.04 LTS (Jammy) (login: ubuntu)
    [ ] Ubuntu 24.04 LTS (Noble) (login: ubuntu)
    [ ] Ubuntu 26.04 LTS (Resolute) (login: ubuntu)

  Selected: 0

  ↑↓ Navigate   SPACE Select/Deselect   ENTER Confirm   Q Back
```

A row that is already built on the pool says `already on this pool` beneath it,
so a re-run is not a guess about what a build would do.

Pick the templates you want and it does the rest — verifying the image against
the origin's published checksum, installing the XCP-ng guest tools, scrubbing
the machine identity a clone must not inherit, and sealing the result. Once
built they appear in Xen Orchestra under **New → VM**, alongside any Hub
templates you already have.

Debian 12 (Bookworm), Debian 13 (Trixie) and the three Ubuntu LTS releases —
22.04 (Jammy), 24.04 (Noble) and 26.04 (Resolute) — are buildable today.
AlmaLinux, CentOS Stream, Fedora and Rocky Linux are listed in the menu as
**Coming Soon...**: each names a published cloud image, and what is missing is a
`dnf` preparation script rather than the image. The full walkthrough — what each
template contains, how the boot firmware is chosen, requirements, and what to do
when a build fails — is in [docs/templates.md](docs/templates.md).

## Configuration

All settings live in `xo-config.cfg`. See
[sample-xo-config.cfg](sample-xo-config.cfg) for full documentation of every
option.

Key settings:

| Option | Default | Description |
|--------|---------|-------------|
| `HTTP_PORT` | 80 | HTTP port |
| `HTTPS_PORT` | 443 | HTTPS port |
| `INSTALL_DIR` | /opt/xen-orchestra | Installation directory |
| `SSL_CERT_DAYS` | 825 | Validity of the generated self-signed certificate, in days |
| `GIT_BRANCH` | master | Git branch or tag |
| `NODE_VERSION` | 24 | Node.js version (latest LTS; use e.g. `24.15.0` to pin a patch) |
| `SERVICE_USER` | root | Service user — root by default; any username runs XO non-root |
| `BACKUP_KEEP` | 5 | Number of backups to retain |
| `TURBO_CACHE_ENABLED` | true | Reuse turbo's local build cache on `--update` instead of rebuilding every package (`--rebuild` always builds cold) |
| `BIND_ADDRESS` | 0.0.0.0 | Bind address |
| `REVERSE_PROXY_TRUST` | false | Trust X-Forwarded headers from proxy IP |
| `PUBLIC_URL` | *(unset)* | Public URL advertised to external entities (e.g. XO Lite) |
| `ENCRYPT_REDIS_CREDENTIALS` | false | Encrypt Redis credentials at rest — XCP-ng guests only (see below) |

Each of these is covered in full, along with the environment variables, in
[docs/configuration.md](docs/configuration.md).

### `ENCRYPT_REDIS_CREDENTIALS`

This is an opt-in xo-server feature that encrypts credentials stored in Redis
at rest (AES-256-GCM). It **only works when Xen Orchestra runs as a VM on a
XenServer/XCP-ng host**, because half of the encryption key is stored in
XenStore. It will **not** work on bare metal or on other hypervisors (KVM,
VMware, Hyper-V). Leave it `false` unless XO is an XCP-ng guest.

**Why the default is `false`, and why plaintext is normal.** The credential
this protects is the one xo-server uses to log into XAPI on your pool.
xo-server has to replay it to XAPI on every connect and auto-reconnect, so it
must be **reversible** — it cannot be hashed the way a login password is.
Storing it in a form xo-server can read back is therefore expected behaviour,
not a defect in XO or in this installer. The security boundary for a default
install is **Redis itself** (bound to localhost, never exposed to the network)
plus **root access on the XO VM**: anyone with either can read the credentials
regardless of this setting. Enabling encryption narrows the blast radius of an
offline disk or snapshot; it does not protect against an attacker who is
already root on a running XO.

**Works with either `SERVICE_USER`:** root reaches XenStore directly. For a
**non-root** `SERVICE_USER`, the xenbus device is root-only by default, so the
installer adds the user to a `xenstore` group and installs a udev rule
(`/etc/udev/rules.d/40-xen-xenbus-xo.rules`) granting access — without this,
xo-server cannot derive the key and credential encryption fails at startup.
Group membership applies on the next service restart; verify with
`sudo -u <SERVICE_USER> xenstore-ls vm-data`. XO's own docs cover only "run as
root or grant access to the xenstored socket" and do not specify the device
permissions, so this part is handled by the installer.

**Requires the Xen guest utilities.** Being a Xen guest is not enough —
`xenstore-read` / `xenstore-write` must be installed (`xe-guest-utilities` on
XCP-ng, or your distro's `xen-guest-utilities` / `xen-utils` package). The
installer warns if they are missing; without them xo-server cannot store its
key half.

> [!WARNING]
> **Before you enable `ENCRYPT_REDIS_CREDENTIALS`, understand the recovery
> story.**
>
> - **Losing one key half is unrecoverable.** The key is split between
>   XenStore (`vm-data/xo-encryption-key`) and
>   `/var/lib/xo-server/data/xo-encryption-key`. If either half goes missing
>   while encryption is on, **do not restart xo-server** — on startup XO
>   treats a missing half as a fresh setup, generates two new halves,
>   overwrites the surviving one, and re-runs the migration while skipping
>   already-encrypted records. Those records become permanently
>   undecryptable. Note that migrating or rebuilding the VM can lose the
>   XenStore half.
> - **`--backup` does not cover the key.** This script's backups copy the
>   install directory only; neither key half lives there. An in-place
>   `--restore` is unaffected (it never touches `/var/lib/xo-server`), but a
>   backup alone **cannot** restore an encrypted database onto a rebuilt VM.
>   The installer prints this reminder when it makes a backup.
> - **Use the config export as your recovery artifact.** With encryption on,
>   exporting the XO config (**Settings → Config** in the web UI) requires a
>   passphrase and produces an OpenPGP-encrypted file. Export a fresh one
>   immediately after enabling encryption, and store it somewhere other than
>   the XO VM.
> - **`--uninstall` destroys the on-disk key half** along with
>   `/var/lib/xo-server`. Redis is left in place, so its records survive as
>   unreadable ciphertext. The installer warns before this when it detects a
>   key file.
>
> Full upstream reference:
> <https://docs.xen-orchestra.com/credential-encryption>

**Opting out:** set `ENCRYPT_REDIS_CREDENTIALS` back to `false` and run
`--reconfigure` — xo-server decrypts the records and removes the key files
automatically. Do this **while both key halves are still intact**.

## Default Credentials

After installation, access the web interface at `https://your-server-ip`.

- **Username:** `admin@admin.net`
- **Password:** `admin`

> [!WARNING]
> **Changing this login is highly recommended, and it is the first thing to do
> after the install finishes — not a later cleanup task.**
>
> These are Xen Orchestra's own published defaults. Every installation in the
> world starts with them, so until you change them, anyone who can reach the
> web interface is a full administrator. Xen Orchestra stores the root
> credentials for every pool you connect to it, so an unchanged default login
> hands over the hypervisors, not just the UI.
>
> 1. Sign in at `https://your-server-ip` as `admin@admin.net` / `admin`
> 2. Open **Settings → Users**, or the account menu → **Profile**
> 3. Set a strong, unique password
> 4. Enable **OTP** (two-factor) on the account while you are there
>
> The installer prints the same reminder when it finishes, and `--deploy`
> repeats it in the deployment summary.

## Supported Operating Systems

- Debian 12/13
- Ubuntu 22.04/24.04/26.04 LTS
- RHEL / CentOS Stream / AlmaLinux / Rocky
- Fedora

Ubuntu is the LTS line. Interim releases have nine-month lifespans and are not
gated, but they are not tested either.

> [!WARNING]
> **Debian 11 (Bullseye) support ends on 2026-10-01.** Debian 11 reached
> end-of-life on **2026-08-31** and no longer receives security updates. Until
> the removal date the installer runs on Debian 11 and prints a warning; from
> **2026-10-01** it refuses to run there unless you pass `--allow-eol-distro`,
> which is unsupported and untested. Upgrade to Debian 12 or 13 before then.

> [!WARNING]
> **Ubuntu 22.04 LTS (Jammy) support ends on 2027-06-01.** Free security
> maintenance for 22.04 ends on **2027-04-30**; after that, updates require a
> paid Ubuntu Pro subscription, which this installer does not assume you have.
> Until the removal date a run on 22.04 warns and continues; from **2027-06-01**
> it refuses unless you pass `--allow-eol-distro`. Upgrade to Ubuntu 24.04 LTS
> or 26.04 LTS before then.

> [!NOTE]
> Continuously smoke-tested in CI on Debian 12/13, Ubuntu 22.04/24.04/26.04 LTS,
> Rocky Linux 9, AlmaLinux 9, CentOS Stream 9, and Fedora — plus Debian 11 until
> its removal on 2026-10-01, and Ubuntu 22.04 until its removal on 2027-06-01.
> RHEL uses the same `dnf` path as its rebuilds; Ubuntu interim releases use the
> same `apt` path as the LTS ones.

> [!NOTE]
> **Firewall:** On Fedora and RHEL-family systems (which enable `firewalld` by
> default and block inbound HTTP/HTTPS), the installer opens the configured
> `HTTP_PORT`/`HTTPS_PORT` automatically. Debian/Ubuntu ship no active firewall,
> so nothing is changed there. If `firewalld` is not running, the step is
> skipped — open the ports yourself if you add one later.

## Running Task Detection (Update Safety)

Before applying an update, the script queries the Xen Orchestra REST API for
active tasks (e.g. running backups, VM exports). If any are found, the update
is aborted to prevent data loss or corruption.

Only **admin-level** XO accounts can access the REST API. Authentication comes
from an auth token, from stored credentials, or from an interactive prompt, in
that order — see
[docs/authentication.md](docs/authentication.md) for how to set one up, and why
API tokens need a description.

## Environment Variables

`XO_DEBUG=1` enables debug mode and `XO_NO_SELF_UPDATE=1` skips the script's
self-update. The `--deploy` variables — image selection, digest and host-key
pinning, and the unattended admin account — are documented in
[docs/configuration.md](docs/configuration.md#environment-variables).

## Troubleshooting

Check service logs:

```bash
sudo journalctl -u xo-server -n 50
```

If the build is broken, rebuild (takes a backup first):

```bash
./install-xen-orchestra.sh --rebuild
```

For OOM build failures, NodeSource GPG errors on offline hosts, git "dubious
ownership", and SELinux denials on RHEL-family systems, see
[docs/troubleshooting.md](docs/troubleshooting.md).

## License

This project is licensed under the [MIT License](LICENSE). Xen Orchestra
itself is licensed under
[AGPL-3.0](https://github.com/vatesfr/xen-orchestra/blob/master/LICENSE).

## Credits

- [Xen Orchestra](https://xen-orchestra.com/) by [Vates](https://vates.tech/)
- [Installation Documentation](https://docs.xen-orchestra.com/install-from-sources)
