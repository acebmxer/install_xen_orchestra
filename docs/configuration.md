# Configuration

[← back to the README](../README.md)

All settings live in `xo-config.cfg`. See
[sample-xo-config.cfg](../sample-xo-config.cfg) for full documentation of every
option.

Key settings:

| Option | Default | Description |
|--------|---------|-------------|
| `HTTP_PORT` | 80 | HTTP port |
| `HTTPS_PORT` | 443 | HTTPS port |
| `INSTALL_DIR` | /opt/xen-orchestra | Installation directory |
| `SSL_CERT_DAYS` | 825 | Validity of the generated self-signed certificate, in days (see below) |
| `GIT_BRANCH` | master | Git branch or tag |
| `NODE_VERSION` | 24 | Node.js version (latest LTS; use e.g. `24.15.0` to pin a patch) |
| `SERVICE_USER` | root | Service user (see below) |
| `BACKUP_KEEP` | 5 | Number of backups to retain (see below) |
| `TURBO_CACHE_ENABLED` | true | Reuse turbo's local build cache on `--update` instead of rebuilding every package (`--rebuild` always builds cold) |
| `BIND_ADDRESS` | 0.0.0.0 | Bind address |
| `REVERSE_PROXY_TRUST` | false | Trust X-Forwarded headers from proxy IP |
| `PUBLIC_URL` | *(unset)* | Public URL advertised to external entities (e.g. XO Lite) |
| `ENCRYPT_REDIS_CREDENTIALS` | false | Encrypt Redis credentials at rest — XCP-ng guests only (see below) |

## `SSL_CERT_DAYS`

825 is the maximum most security policies allow; a longer-lived certificate is
a common audit finding. Existing certificates are never regenerated — delete
the files in `SSL_CERT_DIR` and run `--reconfigure` to reissue.

## `SERVICE_USER`

Root is the default because it avoids permission issues with privileged ports,
NFS/CIFS mounts, XenStore, and VMware V2V import. Set to any username to run
non-root (recommended by the official XO docs) — the script configures the
required sudoers, capability, group, and udev rules automatically. V2V import
requires root.

## `BACKUP_KEEP` rotation

The retention policy only applies to backups created by the current version of
the script. Backups made by older script versions may use a different naming
convention and will **not** be counted or pruned by the rotation logic. If you
are upgrading from an older version, manually review your backup directory
(`BACKUP_DIR` in config, default `/var/lib/xo-backups`) and remove any
legacy-named archives you no longer need.

## `ENCRYPT_REDIS_CREDENTIALS`

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


## Environment Variables

| Variable | Description |
|----------|-------------|
| `XO_DEBUG=1` | Enable debug mode (`set -x`) |
| `XO_NO_SELF_UPDATE=1` | Skip automatic script self-update |
| `XO_DEPLOY_IMAGE_VERSION` | `--deploy`: Debian major version for the guest (default `13`) |
| `XO_DEPLOY_IMAGE_RELEASE` | `--deploy`: Debian codename for the guest (default `trixie`) |
| `XO_DEPLOY_IMAGE_URL` | `--deploy`: full URL of a raw cloud image, overriding the two above |
| `XO_DEPLOY_IMAGE_SHA512` | `--deploy`: expected SHA-512 digest of the cloud image (128 hex characters). See the notes below. |
| `XO_DEPLOY_POOL_FINGERPRINT` | `--deploy`: expected SHA256 host-key fingerprint of the pool master (e.g. `SHA256:abc…`). See the notes below. |
| `XO_DEPLOY_ADMIN_PASSWORD` | `--deploy --non-interactive`: password for the VM's admin account. Required — the deploy refuses to run without it. Minimum 12 characters. |
| `XO_DEPLOY_ADMIN_SSH_PWAUTH` | `--deploy --non-interactive`: set to `true` to allow SSH logins with that password (default `false`, key/console only). |
| `XO_DEPLOY_ADMIN_SSH_KEY` | `--deploy --non-interactive`: path to, or text of, a public key to install on the admin account. See the notes below. |

Notes on the `--deploy` variables:

- **`XO_DEPLOY_IMAGE_SHA512`**: Makes verification mandatory — a digest that
  cannot be checked aborts the deploy, and the streaming import is refused
  outright since it cannot be hashed. Without it, the origin's published
  `SHA512SUMS` is used when available.
- **`XO_DEPLOY_POOL_FINGERPRINT`**: Verified instead of prompting on first
  connection; the deploy aborts before the host password is sent if it does
  not match.
- **`XO_DEPLOY_ADMIN_SSH_KEY`**: Without it the VM ends up console-only, since
  the deployment key is destroyed at the end of the run.

