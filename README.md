# Xen Orchestra Installation for Ubuntu 24.04.3

This installation script sets up Xen Orchestra from source on a fresh Ubuntu Server 24.04.3 installation.

## Quick Start

1. Make the script executable:
```bash
chmod +x install-xen-orchestra.sh
```

2. Run the script as root:
```bash
sudo ./install-xen-orchestra.sh
# install-xen-orchestra

This repository contains `install-xen-orchestra.sh` — an installer that builds Xen Orchestra from sources and configures it to run as the invoking user on Ubuntu 24.04.

Quick summary

- Run as a regular user (do not run as root).
- Uses `sudo` for privileged operations (apt installs, systemd, firewall).
- Generates a self-signed certificate and configures Xen Orchestra to serve HTTPS on ports 80/443.
- Creates a systemd service `xen-orchestra.service` that runs `xo-server` as the invoking user.
- Supports `--dir`, `--domain`, and `--update` flags.

Safe testing / dry-run

If you want to see what the installer will do without making changes, run the included simulator:

```bash
bash simulate-install.sh
```

This prints the major actions the installer would perform (package installs, git clone/pull, build, certificate generation, systemd unit creation and firewall rules) without executing them.

Usage

Run the installer as a normal user (not root):

```bash
bash install-xen-orchestra.sh --domain example.com
```

To check for updates against GitHub and update only if the remote has newer commits:

```bash
bash install-xen-orchestra.sh --update
```

Notes

- The script expects `sudo` available to the invoking user.
- The installer will create files under the chosen install directory (default: `$HOME/xen-orchestra`) and `/etc/xo-server` and `/etc/systemd/system` (requires sudo).
- The installer currently generates a self-signed certificate; replace with a trusted certificate for production.

License: no license specified — use at your own risk.
  listen = [
