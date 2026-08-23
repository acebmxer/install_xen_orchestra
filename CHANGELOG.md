# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This installer builds Xen Orchestra from source and tracks the official
[XO installation documentation](https://docs.xen-orchestra.com/installation#from-the-sources).

## [Unreleased]

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

### Added
- Menu header: the `Master XO Commit` line now shows how many commits the
  installation trails master by (e.g. `efbfb (Branch: master) - 12 commits
  behind`). Shown only when the installed commit is behind; the count is
  computed locally from the install directory's git history.

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

### Changed
- CI ShellCheck now runs at `-S warning` (was `-S error`); intentional
  suppressions live in `.shellcheckrc` and narrowly-scoped inline directives.
- Added `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, and Dependabot for
  GitHub Actions.

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

[Unreleased]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.0.2-alpha...v0.1.0
[0.0.2-alpha]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.0.1-alpha...v0.0.2-alpha
[0.0.1-alpha]: https://github.com/acebmxer/install_xen_orchestra/releases/tag/v0.0.1-alpha
