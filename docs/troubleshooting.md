# Troubleshooting

[← back to the README](../README.md)

Check service logs:

```bash
sudo journalctl -u xo-server -n 50
```

If the build is broken, rebuild (takes a backup first):

```bash
./install-xen-orchestra.sh --rebuild
```

## Build fails with OOM / out-of-memory error

The Yarn build is memory-intensive. On hosts with less than 2 GB RAM the
Node.js process can be killed by the kernel OOM killer mid-build, leaving an
incomplete install.

Add or increase swap to give the build room:

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

Re-run the install or `--rebuild` after the swap is active. To make it
permanent across reboots, add `/swapfile none swap sw 0 0` to `/etc/fstab`.

## NodeSource GPG key failure (air-gapped / offline hosts)

On hosts without internet access (or with strict egress firewall rules) the
NodeSource repository setup script fails because it cannot reach
`keyserver.ubuntu.com` or `deb.nodesource.com`.

**Option A** — pre-download and import the key manually, then copy the
`.deb`/`.rpm` packages to the host.

**Option B** — set `NODE_VERSION` to a specific patch version (e.g. `24.15.0`)
in `xo-config.cfg`. The script will then download a pre-built binary directly
from `nodejs.org` instead of using the NodeSource package repository.

## `git` reports "dubious ownership" and exits

Recent versions of Git refuse to operate on a repository owned by a different
user than the one running the command. This can happen when `sudo` is used
inconsistently or when the install directory was created by `root` but the
script is run as a normal user.

Fix it by resetting ownership to match your `SERVICE_USER`:

```bash
sudo chown -R root:root /opt/xen-orchestra
```

Replace `root` with the value of `SERVICE_USER` in `xo-config.cfg` if you
changed it. Re-running the script afterwards will resolve the rest.

## RedHat / Rocky / AlmaLinux: SELinux denials or systemd capability errors

On SELinux-enforcing systems the `xo-server` service may fail to bind ports or
access network resources. Check for AVC denials:

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

`audit2allow` and `semanage` are provided by the
`policycoreutils-python-utils` package on RHEL/Rocky/Alma.

