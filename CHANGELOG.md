# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This installer builds Xen Orchestra from source and tracks the official
[XO installation documentation](https://docs.xen-orchestra.com/installation#from-the-sources).

## [Unreleased]

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

[Unreleased]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.0.2-alpha...v0.1.0
[0.0.2-alpha]: https://github.com/acebmxer/install_xen_orchestra/compare/v0.0.1-alpha...v0.0.2-alpha
[0.0.1-alpha]: https://github.com/acebmxer/install_xen_orchestra/releases/tag/v0.0.1-alpha
