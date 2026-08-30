# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This installer builds Xen Orchestra from source and tracks the official
[XO installation documentation](https://docs.xen-orchestra.com/install-from-sources).

## [Unreleased]

## [0.4.1] - 2026-08-30

### Added
- **Preflight check for the Xen guest utilities when credential encryption is
  enabled.** `ENCRYPT_REDIS_CREDENTIALS=true` previously only checked that
  `systemd-detect-virt` reported `xen`. A Xen guest without
  `xenstore-read`/`xenstore-write` installed passed that check and then failed
  at xo-server startup, because there was no way to store the key half that
  lives in XenStore. The installer now names the missing tools and the package
  that provides them.
- **`--backup` says what it does not cover.** With credential encryption on,
  the backup now warns that it contains neither half of the encryption key and
  points at the passphrase-protected XO config export as the actual recovery
  artifact. The backup copies the install directory only; an in-place
  `--restore` is unaffected, but a backup alone cannot bring an encrypted
  database back onto a rebuilt VM.
- **`--uninstall` warns before destroying the on-disk key half.** Removing
  `/var/lib/xo-server` deletes this host's half of the encryption key while
  leaving Redis in place, so the records survive as unreadable ciphertext. The
  confirmation prompt now says so when a key file is present.

### Changed
- **Documented why plaintext credentials in Redis are expected, not a defect.**
  The credential xo-server stores is the one it uses to log into XAPI, and it
  is replayed on every connect and auto-reconnect, so it must be reversible and
  cannot be hashed. The README and sample config now explain that the perimeter
  on a default install is localhost-bound Redis plus root on the XO VM, and
  what enabling encryption does and does not buy. This was the single most
  common question about the setting and the docs did not answer it.
- **Documented the credential-encryption recovery caveats.** The README, the
  sample config, the comments written into migrated `xo-config.cfg` files, and
  the generated `/etc/xo-server/config.toml` now all carry the same warnings:
  the key is split between XenStore and `/var/lib/xo-server/data`, losing
  either half while encryption is on makes the records permanently
  undecryptable (do not restart xo-server in that state), and the config export
  requires a passphrase once encryption is enabled.
- **Flagged the network exposure of a remote `REDIS_URI`.** The sample config
  offered `redis://redis.company.lan:6379/42` as an example with no comment.
  Redis speaks an unencrypted protocol and holds the pool credentials, so
  pointing it off-host sends them over the network in cleartext and moves them
  outside XO's trust boundary. The example is still there, now with the warning
  it needed and the loopback/socket alternatives listed first.
- Softened an unverified claim that a non-root xo-server without XenStore
  access "rejects logins (degraded mode)"; the observable behaviour documented
  is now that credential encryption fails at startup.

## [0.4.0] - 2026-08-23

### Changed
- **The cloud image is staged on the pool master by default instead of being
  streamed.** Staging is the only path that can resume a broken download, retry
  a transient failure, and check the downloaded size before anything reaches the
  VDI; streaming can do none of those, because a pipe already feeding a
  fixed-`Content-Length` PUT cannot be rewound. On a link that drops the
  occasional TLS record — which any multi-gigabyte transfer eventually meets —
  streaming failed every attempt while staging rode it out. Streaming is now
  what it should always have been: the fallback for a host without the few
  gigabytes of scratch space staging needs.

### Fixed
- **A stalled streaming import no longer has to be interrupted by hand.** When
  the download end died, the upload sat waiting for a response XAPI would never
  send. `--speed-time` could not help — by that point curl is waiting, not
  transferring, so the speed meter has stopped ticking and only `--max-time
  3600` would eventually fire. The two transfers now run as separate processes
  with the download's exit status watched, and the upload is killed the moment
  it fails.
- **A pool master short on scratch space no longer fails the whole deploy.**
  The staged path signalled "no room" with a plain non-zero return, which under
  `set -e` took the script down before the fallback could be reached.
- **A failed cloud-image download no longer looks like a successful import.**
  The streaming import piped one `curl` into another, and the remote shell
  reported only the *upload* side's exit status. A download that died partway —
  a transient `SSL_read ... bad record mac` on a 3 GB transfer is the usual
  cause — therefore produced a truncated disk that the deploy reported as
  imported, and a VM that booted into a corrupt filesystem. The pipeline now
  runs under `bash -o pipefail`.
- **A broken image download no longer hangs the deploy for an hour.** When the
  download end died, the upload `curl` had already promised XAPI an exact
  `Content-Length` and sat waiting to send bytes that were never coming, with
  XAPI waiting alongside it until `--max-time 3600` expired — the visible
  symptom being a XAPI task frozen at partial progress and a script that had to
  be interrupted. Both ends now abort after 60s below 1 KiB/s.
- **The staged image download resumes instead of starting over.** It now uses
  `-C -` with `--retry 5 --retry-delay 3 --retry-all-errors`, so the transient
  TLS failures that a multi-gigabyte single-connection download eventually hits
  are ridden out rather than failing the deploy. The streaming path deliberately
  does *not* retry: `curl` re-issues from byte 0, and piped into a
  fixed-`Content-Length` PUT those bytes would be appended to the ones already
  sent, corrupting the image while appearing to succeed.
- **A short staged download is refused rather than imported.** The file's size
  is now checked against the length the server advertised before anything is
  written into the VDI.
- **The staged download reports progress.** It was silent for several minutes
  on the longest step of the deploy, which reads as a hang worth killing.
- **A failed deploy names the VM it left behind**, with the `xe vm-destroy`
  command, instead of leaving a half-built VM to be rediscovered later in the
  pool's VM list. Nothing is destroyed automatically.
- **`--update`/`--reconfigure`/`--rebuild` no longer abort on a root install.**
  Reading `User=` from a systemd unit that has no such line (which is what a
  root install looks like) failed the pipeline under `set -o pipefail` and took
  the script down before the fallback could run.
- **Deploy prompts validate values, not just their shape.** `999.999.999.999`
  was accepted as an address and `70000` as a port; both were only rejected
  after the VM existed, by an unreachable guest or by the installer inside it.
- **Prompted settings are no longer lost when the base config omits the key.**
  The generated `xo-config.cfg` was patched with `sed`, which silently does
  nothing for a key that is not there — so the VM installed on the default
  while the summary showed the value you typed. Missing keys are now appended.
- **An `$EDITOR` with arguments works.** `code --wait` passed the availability
  check and then failed with "No such file", since the whole string was treated
  as one executable path.
- **Values edited into the config are validated.** An unusable port or branch
  was silently ignored, leaving the summary showing one thing and the VM
  installing another.
- **Troubleshooting commands point at a key that still exists.** The `ssh -i`
  lines printed on a failed install and on a non-200 health check named the
  temporary key, which the exit trap had already deleted.
- **A second VM with the same hostname no longer overwrites the first one's
  SSH key**, which was the only way into that machine.
- The disk-space check before staging an image on the pool master is derived
  from the image's actual size instead of a hard-coded 4 GiB, which rejected
  small images and let large ones fill `/var/tmp` mid-download.
- `tests/probe-xapi-deploy.sh` acquires its XAPI session from the pool master,
  the way `--deploy` does, so a firewall that blocks port 443 from your
  workstation no longer skips the HTTP transport probes that matter. It also
  validates `--host`, `--user`, `--sr`, `--image` and `--payload-mb` before
  they reach a shell, drops the `eval` in the workstation-side transport, and
  exits non-zero when any probe failed rather than whenever one transport
  worked.
- The menu example in the README and the layout comment above `MENU_NAMES`
  described the old fixed 5/4/centered grid; with ten items the menu draws five
  entries in each column.
- Passwords containing `&`, `<` or `>` are XML-escaped before being sent to
  XAPI, instead of producing a malformed request and an unexplained login
  failure. Same fix in `tests/probe-xapi-deploy.sh`.

### Security
- **The cloud image is verified against its published checksum.** The size
  check catches a download that was cut short; it cannot catch one that arrived
  complete from the wrong place, because a substituted image has a perfectly
  consistent `Content-Length`. The staged image is now checked against the
  `SHA512SUMS` its origin publishes beside it — which is what Debian ships —
  and a mismatch aborts before anything reaches the disk. An origin that
  publishes no sums warns and continues, so a custom `XO_DEPLOY_IMAGE_URL`
  keeps working. Set `XO_DEPLOY_IMAGE_SHA512` to require a specific digest
  instead: that makes the check mandatory, aborting rather than continuing
  unverified, and refuses the streaming import outright because a pipe fed
  straight into the VDI leaves no file to hash. Fetching sums over the same
  connection as the image is not a detached signature — it defends against a
  bad mirror or a stale cache, not an attacker holding the TLS session for
  both requests.
- **A pinned pool-master fingerprint is now enforced instead of advised.**
  `deploy_verify_host_key` fingerprinted the host key and then returned success
  on every path that could not complete the check — so with
  `XO_DEPLOY_POOL_FINGERPRINT` set, a `ssh-keyscan` that timed out meant the
  host password was sent to whatever answered on that address, which is exactly
  what pinning exists to prevent and the easiest outcome for an on-path attacker
  to arrange. A pin that cannot be checked is now a hard failure.
- **The verified host key is bound to the connection that carries the password.**
  The scanned key was fingerprinted, shown, and then discarded, while
  `dom0_exec` connected with `StrictHostKeyChecking=accept-new` against the
  default `known_hosts` — verifying one transaction and trusting another.
  Nothing stopped a different key, or the host's RSA key when the ED25519 one
  had been displayed, being accepted at connect time. The whole scan is now
  pinned into a run-scoped `known_hosts` that `dom0_exec` enforces with
  `StrictHostKeyChecking=yes`, the same way `deploy_wait_for_guest` already
  treated the guest.
- **A hostile pool master can no longer run commands on the workstation.** The
  free-space probe in `deploy_import_vdi_staged` fed the host's reply straight
  into `(( ))`, which expands an array subscript before evaluating it — so an
  answer of `PATH[$(...)]` executed locally rather than being rejected. It is
  now checked against `^[0-9]+$` first, matching the guards already applied to
  `size` and `got` in the same function. Note that `set -euo pipefail` does not
  cover this: `set -u` blocks only the unbound-variable form of the payload.
  This mattered more after staging became the default import path, because the
  probe went from rarely reached to running on every deploy.
- **The pool master's root password is no longer visible in `ps`.** Three calls
  predating `dom0_exec` still used `sshpass -p "$HOST_PASSWORD"`, putting the
  password in the process list where any other user on the workstation could
  read it. They now use `sshpass -e` with `$SSHPASS`, as `dom0_exec` does.
- **The admin password hash is kept out of `XO_DEBUG=1` output.**
  `deploy_harden_guest_sudo` and `deploy_build_config_drive` were missing the
  `local -` / `set +x` guard the rest of the script uses, so the hash was
  printed by xtrace. Previously masked on automated runs only because
  `--non-interactive` left the hash empty; requiring a password made it
  reachable on every deploy.
- **Revoking the deployment key can no longer empty `authorized_keys`.** A
  `grep` failure — no space for the temporary file, an unreadable source — was
  swallowed by `|| true` and the empty result written back, taking the
  operator's own key with it. grep's "nothing matched" (a legitimate empty
  result) is now distinguished from a real error, which aborts and leaves the
  file untouched.
- **The streaming import's FIFO is created inside a private directory.**
  `mktemp -u` returns a name without creating anything, leaving a window in
  dom0's world-writable `/tmp`. The FIFO now lives in a `mktemp -d` directory.
- **DSA public keys are rejected.** `ssh-dss` was accepted by
  `deploy_load_pubkey`, but OpenSSH has refused DSA since 7.0 and removed it in
  9.8, so it only installed a key that silently never worked.
- **The cloud-init cache scrub covers `cloud-config.txt`.** The rendered config
  holds `hashed_passwd` just as the raw user-data does; only the latter was
  being redacted.
- **The deployment SSH key is destroyed at the end of a deploy.** It used to be
  saved next to the script as `xo-deploy-<hostname>.key` and handed to the
  operator as the way into the VM — an unencrypted, passphraseless private key
  granting root-equivalent access, sitting in a git working tree for the life
  of the machine. It is now a throwaway credential for the install only: the
  private half never leaves the run's mode-700 temporary directory and is
  shredded on exit, and the public half is removed from the guest's
  `authorized_keys` as the deploy's last step, with the removal verified by a
  connection attempt that must fail. **Any `xo-deploy-*.key` left by an earlier
  version still works against its VM** — remove its line from that VM's
  `authorized_keys` and delete the file.
- **`--deploy` installs a public key you own instead.** A prompt offers your
  `~/.ssh/id_ed25519.pub` (or ECDSA/RSA equivalent), accepts any path, and takes
  `XO_DEPLOY_ADMIN_SSH_KEY` under `--non-interactive`. Private keys are rejected
  rather than embedded into cloud-init's user-data, where they would be readable
  by anyone on the guest. Declining is supported and leaves a console-only VM,
  which the summary states plainly along with how to add a key later.
- **The VM's admin password is now required, minimum 12 characters.** It was
  optional, and skipping it produced an account reachable only by the generated
  key — which is now destroyed, so such an account would be unreachable and its
  `sudo` could not be hardened. `--non-interactive` takes it from
  `XO_DEPLOY_ADMIN_PASSWORD` and refuses to run without it, rather than silently
  creating a passwordless account. A missing `openssl`/`mkpasswd` is now a hard
  error instead of a quiet downgrade.
- **`--deploy` revokes the passwordless sudo it needed for the install.**
  cloud-init grants `ALL=(ALL) NOPASSWD:ALL` because the unattended install runs
  over SSH with no TTY to answer a password prompt, but that grant used to
  outlive the install, turning the (passphraseless) deploy key into
  unauthenticated root on the appliance. The rule is now rewritten to the
  ordinary `ALL=(ALL:ALL) ALL` once the install returns, validated with `visudo`
  before and after and rolled back if the sudoers tree stops parsing. It is
  skipped for a key-only admin account, where requiring a password would be a
  lockout rather than hardening, and the summary says which mode the VM is in.
- **The admin password hash no longer survives the config drive.** Destroying
  the cloud-init VDI left the copies cloud-init had already cached in the guest
  (`/var/lib/cloud/instance/user-data.txt` and friends) plus any occurrence in
  the DEBUG-level cloud-init log Debian ships enabled. Both are now redacted
  after the install.
- **Deployed VMs are patched on first boot and stay patched.** The stock cloud
  image is only current to its build date, so the web UI came up on a package
  set that could be a month or more behind. `--deploy` now performs a full
  package upgrade during cloud-init and installs `unattended-upgrades`, with
  `/etc/apt/apt.conf.d/20auto-upgrades` written explicitly rather than left to
  a debconf default that varies between releases.
- **The pool master's SSH host key is checked on first contact.** The host
  password is sent over that connection, and while `ssh` rejects a *changed*
  key on its own, first contact had nothing to compare against. The fingerprint
  is now shown for confirmation, or verified without a prompt against
  `XO_DEPLOY_POOL_FINGERPRINT`, aborting before the password is sent on a
  mismatch.
- **Self-signed certificates are no longer issued for ten years.** The default
  lifetime drops from 3650 days to 825, the ceiling most security policies
  inherited from the CA/Browser Forum, and is configurable through the new
  `SSL_CERT_DAYS` setting. Existing certificates are untouched; delete them and
  run `--reconfigure` to reissue.
- **The default web login is called out as a first-run task.** `admin@admin.net`
  / `admin` are Xen Orchestra's published defaults, and this appliance holds the
  root credentials of every pool connected to it. The install summary, the
  `--deploy` summary, and the README now spell out what is at stake and give the
  steps to change it, including enabling OTP. The deploy summary also warns that
  the saved SSH key has no passphrase and shows how to add one.
- **`--deploy` no longer writes the pool password to dom0's disk.** The XAPI
  login body went to a fixed `/tmp` path on the pool master, readable by any
  other local account for the duration of the request and liable to collide
  with a concurrent deploy. It is now piped straight into `curl` over the
  existing SSH connection, so it exists only in memory on both ends.
- **`XO_DEBUG=1` no longer traces passwords.** Tracing was switched back on
  immediately after the pool password was read, so `set -x` then printed it on
  every `sshpass` call and in the XAPI request body, contradicting the "sensitive
  values are masked" note at the top of the script. Every function that handles
  the pool password or the guest's console password now keeps tracing off for
  its duration.
- **Credentials and SSH remotes are no longer copied into the guest.** The VM
  clones from this checkout's `origin`; an HTTPS remote carrying a token would
  have put that token in the guest's world-readable cloud-init data, and an SSH
  remote would simply have failed to clone in a VM that has none of your keys.
  Origins are now rewritten to a plain HTTPS URL with any userinfo stripped.
- **The guest's SSH host key is pinned after the first connection.** The
  installer used to accept any host key on every connection to the new VM,
  leaving a window in which something else at that address could receive
  `xo-config.cfg`.
- **An aborted deploy no longer abandons the cloud-init config drive.** It
  carries the guest's private key and, if you set one, the admin password hash.
  When the VM was never started the drive is removed outright; once it is
  running (where destroying the drive could break a machine you are about to
  debug) the exact removal commands are printed.
- **Switching `SERVICE_USER` to root now fully revokes the old account's
  XenStore access.** Removing the udev rule left the previous user in the
  `xenstore` group and left `/dev/xen/xenbus` group-owned by it; both are now
  undone.

## [0.3.0] - 2026-08-22

### Added
- **`--deploy`: create a VM and install Xen Orchestra into it.** Aimed at
  newcomers who have a XenServer/XCP-ng pool but no Linux VM to install onto,
  and the only operation here that runs on your workstation instead of on the
  target machine. It opens one multiplexed SSH connection to the pool master
  and drives `xe` over it, so nothing beyond `ssh`/`sshpass` and an ISO writer
  is needed locally. A stock Debian 13 cloud image is streamed from
  `cloud.debian.org` directly into the new VM's disk *by the pool master*, so
  the 3 GB never crosses your link and never lands on dom0's root filesystem —
  and there is no appliance image for this project to build, host, or keep
  patched. Disk import goes through XAPI's `/import_raw_vdi` HTTP endpoint
  rather than `xe vdi-import`: on XCP-ng 8.3 the latter fails with
  `VDI_IO_ERROR` when fed a pipe, because XAPI needs a seekable source of
  known length. The endpoint also rejects chunked encoding, so the length is
  read from the image server and supplied by hand, and the body is streamed
  with `curl -T -` rather than `--data-binary @-` — the latter buffers the
  whole body in RAM and dies with "out of memory" well below a 3 GB image.
  A cloud-init config drive creates the admin user, installs a
  generated SSH key, applies the static address, and clones this repository
  into the guest — either `/opt/install_xen_orchestra` or the admin's home
  directory, whichever you pick at the prompt. The admin account can also be
  given a password (hashed locally with `openssl passwd -6`, or `mkpasswd`):
  it is optional, since the account always gets the SSH key, and exists for the
  VM's console where no key can be offered. SSH stays key-only unless you
  answer yes to the follow-up prompt. The config drive is detached and
  destroyed once the install succeeds — cloud-init has cached its result and
  netplan's config lives on the root disk by then, so keeping it would only
  leave the password hash readable to anyone who can attach a VDI, and re-seed
  cloud-init (static IP included) on any clone of the VM. The VM's
  `xo-config.cfg` is built from `sample-xo-config.cfg`, or from your own
  `xo-config.cfg` if you keep one beside the script and pick it when asked;
  either way `--deploy` then offers to open the generated file in an editor
  before anything is created on the pool, which is the only way to set the
  options it does not prompt for (`INSTALL_DIR`, `SERVICE_USER`,
  `NODE_VERSION`, SSL and backup paths) without editing the tracked sample.
  Editing happens on a copy in the work directory, so neither the sample nor
  your own config is touched, and any ports changed there are read back so the
  review screen, post-install check and summary agree with the file. The
  install itself then runs over SSH as
  `--install --non-interactive` with its output streamed to your terminal, so
  failures are visible instead of buried in the guest's cloud-init log.
  Available as `--deploy` or from the interactive menu. A static IP is
  required: a stock cloud image has no `xe-guest-utilities`, so a DHCP lease
  cannot be read back from the host. Guest image selection is overridable via
  `XO_DEPLOY_IMAGE_VERSION`, `XO_DEPLOY_IMAGE_RELEASE`, and
  `XO_DEPLOY_IMAGE_URL`.
- `tests/probe-xapi-deploy.sh`, a diagnostic that checks `--deploy`'s XAPI
  assumptions against a real pool master — the parts the BATS suite cannot
  reach without a hypervisor. Verifies SR/network enumeration, the host's
  outbound internet access, `vdi-import` from both a dom0-local pipe and SSH
  stdin (round-tripped through `vdi-export` and checksummed, since an exit code
  of 0 does not prove the bytes landed), the `/import_raw_vdi` HTTP fallback,
  and VM creation with the boot/CPU/memory parameters deploy sets. Everything
  it creates is tagged `xo-probe-<run id>` and torn down on exit including on
  failure; it never modifies or starts anything it did not create.
- `TURBO_CACHE_ENABLED` config option (default: `true`). Enables turbo's local
  build cache so `--update` reuses unchanged packages' build output instead of
  rebuilding all 25 packages every time. `--rebuild` always does a clean,
  cache-free build regardless of this setting. Set to `false` to restore the
  previous always-cold-cache behavior.
- Migration cleanup when `SERVICE_USER` is switched to `root`. Previously every
  service-user cleanup branch was guarded by `[[ "$SERVICE_USER" != "root" ]]`,
  so switching to root skipped them all and left the old account's
  `/etc/sudoers.d/xo-server-<user>` grant (NOPASSWD mount/umount/findmnt) and
  the `40-xen-xenbus-xo.rules` udev rule in place. `--update`, `--reconfigure`,
  and `--rebuild` now read the outgoing user from the systemd unit before
  rewriting it and remove both. The account itself is reported, not deleted —
  it may own unrelated files — with the exact `userdel` command to run.

### Changed
- The menu's two-column grid is derived from the item list instead of being
  written down beside it. An even number of items now fills two equal columns;
  an odd number splits them evenly and centers the leftover item beneath, as
  the layout always intended. Ten items previously drew as 5/4 with one
  stranded in the middle, because the counts were hardcoded when the list was
  shorter. Column wrapping follows suit: with no centered row, up from the top
  of a column now returns to its bottom rather than refusing to move.
- **`SERVICE_USER` now defaults to `root`** (was `xo-service`). Running as root
  avoids permission problems with privileged ports, NFS/CIFS remote mounts,
  XenStore access, and VMware/ESXi V2V import, and matches what the XOA
  appliance and other from-source installers do. Non-root remains fully
  supported and is still what the official XO docs recommend — set
  `SERVICE_USER` to any username and the installer configures the sudoers
  rule, `CAP_NET_BIND_SERVICE`, `xenstore` group, and udev rule as before.
  **Existing installs are unaffected** unless you edit `xo-config.cfg`: the
  value in your existing config is preserved.
- `build_xo`'s `TURBO_CACHE` now defaults to `local:rw` (was `remote:r`, which
  disabled all caching since no `TURBO_TOKEN`/`TURBO_TEAM` is configured).
- `--update` no longer forces a clean build (`build_xo clean` → `build_xo`),
  so it can benefit from the local cache. `--rebuild` is unchanged and still
  wipes the cache for a guaranteed fresh build.

### Fixed
- The interactive menu crashed on launch with
  `MENU_SELECTED[$idx]: unbound variable`. Adding the "Deploy Xen Orchestra to
  a new VM" entry took the menu to ten items and grew the `MENU_SELECTED`
  declaration to match, but `run_menu` reset the same array to a hardcoded
  nine zeroes, so drawing the tenth item read past the end of it. The reset is
  now sized from `MENU_TOTAL`, and `tests/unit/test_menu_layout.bats` asserts
  the parallel menu arrays stay in step.
- XO 5's About page reported the *previous* commit after a successful update
  and kept claiming the install was behind master. `xo-web`'s build bakes the
  commit into its bundle (`GIT_HEAD=$(git rev-parse HEAD)` in its `build`
  script, read as `process.env.GIT_HEAD` and inlined by `loose-envify`), but
  turbo hashes a package's files rather than the checked-out commit — so any
  update whose diff didn't touch `packages/xo-web/` restored a cached `dist`
  carrying the old commit. `build_xo` now exports `GIT_HEAD` and writes an
  untracked `packages/xo-web/turbo.json` adding it to that task's cache key,
  so xo-web rebuilds whenever the commit changes while the rest of the
  workspace stays cached. Only the displayed commit was ever wrong; the code
  in a cache-hit `dist` was correct.

## [0.2.1] - 2026-07-29

### Added
- Menu header: the `Master XO Commit` line now shows how many commits the
  installation trails master by (e.g. `efbfb (Branch: master) - 12 commits
  behind`). Shown only when the installed commit is behind; the count is
  computed locally from the install directory's git history.

### Fixed
- Swap check no longer deletes and recreates the swap file on every build:
  `free -m` reports a 2048MB swap file as 2047MB (mkswap header + rounding), so
  the exact `>= 2048` comparison failed by 1MB forever. The check now tolerates
  a 16MB shortfall.
- Build concurrency limit is now passed via the `TURBO_CONCURRENCY` environment
  variable instead of `yarn build --concurrency=N`. Yarn 1 appends extra args to
  the end of the script string, and upstream's `build` script now ends with
  `&& yarn build:doc` (xen-orchestra commit `ada3cf7`, PR #10154), so the flag
  cascaded into `docusaurus build` — which rejects it with
  `error: unknown option '--concurrency=1'` and aborted low-memory updates —
  while turbo itself never received the limit.

## [0.2.0] - 2026-07-15

### Added
- `--version` flag: prints the script's release (via `git describe`) and branch.
- Firewall: on Fedora/RHEL-family hosts running `firewalld`, the installer now
  opens the configured `HTTP_PORT`/`HTTPS_PORT` automatically (no-op where
  firewalld is absent or stopped). Applied on install, `--reconfigure`, and
  `--rebuild`.
- CI: expanded the integration matrix to Debian 11/13, AlmaLinux 9,
  CentOS Stream 9, and Fedora (alongside the existing Debian 12, Ubuntu 24.04,
  and Rocky Linux 9) so every supported distro family is smoke-tested.
- Added `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, and Dependabot for
  GitHub Actions.

### Changed
- CI ShellCheck now runs at `-S warning` (was `-S error`); intentional
  suppressions live in `.shellcheckrc` and narrowly-scoped inline directives.

### Fixed
- Guard the `free`-based memory/swap detection so a missing `free` (e.g. minimal
  images without `procps-ng`) can't abort the script under `set -e`; falls back
  to the conservative low-memory path. Fixes the Rocky Linux integration test.
- Server-IP detection for the install/reconfigure summaries no longer aborts on
  minimal hosts without `hostname`/`ip` (new `detect_server_ip` helper always
  succeeds, falling back to a placeholder). Fixes the Fedora integration test.
- Fedora: no longer runs the RHEL-only `epel-release` install and
  `dnf config-manager --enable devel` (both error on Fedora); Valkey is
  installed straight from Fedora's base repositories.
- Fedora: `setup_redis` now detects and starts the `valkey` service reliably
  (previously failed with "Neither redis nor valkey service found"), with a
  `valkey-cli` fallback and clearer diagnostics on failure.
- systemd unit now orders `xo-server` after `valkey.service` in addition to
  `redis.service` (applies to new installs and `--reconfigure`).

## [0.1.3] - 2026-06-04

### Added
- Support for a non-root `SERVICE_USER` with Redis credential encryption,
  including XenStore access via a `xenstore` group and a udev rule.
- `nbdinfo` (libnbd) installation for a non-root `SERVICE_USER` so ESXi/VMware
  (V2V) imports work without running xo-server as root.
- Config schema **v2**: `PUBLIC_URL` and `ENCRYPT_REDIS_CREDENTIALS` options,
  with automatic, non-destructive migration of an existing `xo-config.cfg`.
- `--adjust-memory` to raise the xo-server Node heap (`--max-old-space-size`).
- `--flush-tokens` flag plus orphaned-token diagnostics.
- Auth retry on HTTP 401 during the pre-update task check, with credential
  re-entry.

### Changed
- Preserve API tokens (those with a description) when flushing stale session
  tokens from Redis during updates; classify tokens by `client_id`.
- Reload the script after a config rename or edit.
- Removed the `configure_redis_persistence` function.

### Fixed
- Skip systemd capability hardening when the service runs as root (avoids
  stripping capabilities root needs).
- Regenerate `config.toml` correctly when both `REDIRECT_TO_HTTPS` and
  `REVERSE_PROXY_TRUST` are set (previously produced a duplicate `[http]`
  section). Apply the fix with `--reconfigure`.
- Handle the XO 6 dual web UI and stale Redis index keys.
- Avoid `chown -R` over active mount points under `/run/xo-server`.
- Add timeouts to `redis-cli` and `systemctl stop` calls.
- Use `sudo` for filesystem checks in `verify_xo_web_build`; add diagnostics
  for missing XO 6 web UI build artifacts.

## [0.1.2] - 2026-04-25

### Changed
- Default Node.js bumped to 24.15.0 LTS.

## [0.1.1] - 2026-04-25

### Added
- Automation flags (`--non-interactive`/`--yes`, `--dry-run`/`--check`,
  `--log-file`, `--json-logs`), `--uninstall`, a run lockfile, and CI
  (ShellCheck, BATS unit tests, multi-distro integration).
- Token- and credential-based auth for the pre-update XO task check.
- Restore Backup option in the interactive menu.

### Changed
- Pin `actions/checkout` to v4.2.2 in CI.

### Fixed
- Patch the `@xen-orchestra/rest-api` prebuild hook for npm 11 compatibility.
- Use Corepack for the Yarn install; clear the npm cache.
- Prevent self-update failure caused by an untracked `xo-config.cfg`.
- Expand `CapabilityBoundingSet` so sudo and NFS/CIFS mounts work under a
  non-root service user; add `LimitNOFILE`/`LimitMEMLOCK`.

## [0.1.0] - 2026-03-24

### Added
- Interactive two-column TUI menu with keyboard navigation.
- Script self-update from the current branch.
- XO Proxy installation (`--proxy`).

### Changed
- README rewritten as a concise reference guide.

## [0.0.2-alpha] - 2026-02-23

### Added
- Reverse-proxy support (`REVERSE_PROXY_TRUST`).

## [0.0.1-alpha] - 2026-02-22

### Added
- Initial public release: install / update / restore / rebuild Xen Orchestra
  from source with a self-signed certificate and a systemd service;
  configurable service user.

[Unreleased]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.0.2-alpha...v0.1.0
[0.0.2-alpha]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.0.1-alpha...v0.0.2-alpha
[0.0.1-alpha]: https://github.com/acebmxer/install_xen_orchestra/releases/tag/v0.0.1-alpha
