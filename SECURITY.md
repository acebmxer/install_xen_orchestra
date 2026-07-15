# Security Policy

## Supported Versions

This project is a single installer script; only the **latest release** on the
`main` branch receives fixes. The script self-updates by default, so before
reporting an issue please confirm you are on the current version:

```bash
./install-xen-orchestra.sh --version
```

| Version                  | Supported          |
| ------------------------ | ------------------ |
| Latest release (`main`)  | :white_check_mark: |
| Older tags               | :x:                |

## Reporting a Vulnerability

Please report security issues **privately** — do not open a public issue for a
suspected vulnerability.

Use GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Include the affected version (`./install-xen-orchestra.sh --version`), a
   description, reproduction steps, and the impact.

Expect an initial acknowledgement within a few days. Once a fix is available it
will land on `main` and be noted in [CHANGELOG.md](CHANGELOG.md).

## Scope

This policy covers the installer script and its helper files in this
repository. Because the script configures `sudo` rules, a systemd service, and
(optionally) a non-root service user, pay particular attention to:

- generated entries under `/etc/sudoers.d/`,
- the `xo-server` systemd unit,
- file ownership and permissions under `/etc/xo-server`, `/var/lib/xo-server`,
  and the install directory.

Vulnerabilities in **Xen Orchestra itself** (not this installer) should be
reported upstream at
<https://github.com/vatesfr/xen-orchestra/security/policy>.
