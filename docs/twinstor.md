# TwinStor (`--twinstor`)

[← back to the README](../README.md)

TwinStor is Vates' **tech preview** that turns the local disks of a two-host
XCP-ng pool into one shared, replicated storage repository, with no SAN and no
third host. Vates' own pages describe it:

- [Deployment guide](https://cdn.vates.tech/twinstor/deploy/)
- [Documentation](https://docs.vates.tech/tech-preview/twinstor/)

> **Lab pools only.** Vates distributes this as a pre-release test build and says
> not to run it in production. Setup **erases a disk or partition on each host**. Keep backing
> up your VMs: two copies protect against hardware failure, not against a deleted
> VM or ransomware.

```bash
./install-xen-orchestra.sh --twinstor           # the TwinStor menu
./install-xen-orchestra.sh --twinstor-upgrade   # update both hosts, one at a time
```

It is also the **TwinStor** entry in the interactive menu. Nothing is installed
on the machine running the script; the work happens on the pool's hosts over SSH.
`--non-interactive` is refused, and `--dry-run` stops at once, because nothing
here can be simulated.

## Connecting

The script asks for the pool master's address, user and password, exactly as
`--deploy` does, and checks the master's SSH host key before the password is sent.
It then lists the pool's hosts and does the same host key check for the other
host, using the master's password: a host joins a pool with the master's root
password.

## The menu

The TwinStor menu is shown first, before anything connects, so backing out costs
nothing.

| Entry | What it runs |
| --- | --- |
| Install | The steps below |
| Update | One host at a time: new bundle, `twinstor upgrade-apply --check`, `twinstor upgrade-apply --yes`, then waits until that host is healthy before the next. `--twinstor-upgrade` goes straight here |
| Status | `twinstor --version`, `twinstor status` and `twinstor doctor` on both hosts, then the pool's HA settings |
| Support bundle | `twinstor support-bundle` on both hosts, copied back to the current directory and removed from the hosts |

## Installing

1. **Checks, read only.** The pool must have exactly two hosts (if it has one, the
   script can join a second after a typed confirmation, because a pool join
   replaces that host's root password and discards its configuration). Both must
   run XCP-ng 8.3 at the same patch level, and every SR must be plugged on every
   host, because a host whose SR fails to plug stays disabled after a reboot. dom0
   memory is compared with Vates' rule of thumb (1 GiB + 16 MiB per VM, plus 30%,
   counting the VMs of both hosts), and the script offers to set it for the next
   boot. It cannot check the BIOS setting "Restore on AC power loss = Power On"
   or the link speed between the hosts, and says so.
2. **Network mode,** which cannot be changed later without a maintenance window:
   *fate-shared* (the default; hosts and gateway on the same network or switch
   pair) or *arbitrated* (a dedicated storage network plus a direct cable between
   the hosts, for which it asks the two direct-link addresses).
3. **Data device for each host: a disk or a partition.** The script lists the free
   disks and partitions on the host, using the reasons `twinstor setup` itself
   gives for not offering a device:
   - a disk that already has partitions is not offered, but its free partitions
     are, so a spare partition on a data disk works;
   - nothing that is mounted, used as swap, an LVM physical volume, or under a
     RAID array (or LVM, multipath, DRBD) is offered;
   - on the system disk only a partition labelled `twinstor-data` is offered
     (`sgdisk -c <number>:twinstor-data /dev/<disk>`).

   You can also type a path for a partition, an md-RAID array or a ZFS zvol
   (`/dev/zvol/<pool>/<dataset>`, which must have `sync=standard`; Vates supports
   ZFS only as a community option). Vates asks for the stable
   `/dev/disk/by-id` path, because `/dev/sdX` can name a different disk after a
   restart, so a typed `/dev/sdb2` is turned into its by-id name (a partition's
   ends in `-part2`), and the script warns if a device has none.
4. **Optional extra tie-breaker addresses** (a second router, a switch management
   address), passed to setup as `--ping-target`. The direct-link address is
   refused. Setup needs at least one tie-breaker, a default gateway or one of
   these, so the script stops before erasing anything if a host has neither.
5. **Typed confirmation.** The summary names the disks or partitions that will be
   erased; you type `WIPE` to go on.
6. **Install the bundle on both hosts.** `TWINSTOR_VERSION` and `TWINSTOR_SHA256`
   in `xo-config.cfg` pin the bundle (see below). The script downloads it on the
   host, checks the SHA-256, and only then extracts it and runs Vates'
   `install.sh`, which does its own checks, installs the bundled packages and
   the binary, and starts the shutdown-safety unit. A mismatch deletes the
   download and stops. About 500 MiB of free space is needed in `/root`.
7. **Setup,** as Vates documents it for scripted installs. On the first host:
   `twinstor setup --peer-ip <second host> --backing-device <its device>
   --chap-password <password> --yes`. The script waits until that host reports it
   is ready for the second (erasing and preparing a large disk can take hours),
   then runs the same on the second host with the first as its peer. The CHAP
   password is generated for this run and given to both, so nothing is read back
   from the first host's output, and it is hidden from everything the script
   prints. Arbitrated mode adds `--direct-ip <the peer's end of the direct
   link>`, which setup only accepts when the direct link already has its static
   address on both hosts. When setup's `--help` lacks a flag, or the direct link
   has no address yet, the wizard runs by hand instead: it starts on the first
   host in your terminal, and you run `twinstor setup` on the second host in
   another terminal. The script tells you exactly what to answer.
8. **Verify.** Waits up to 30 minutes per host for `twinstor status` to report
   healthy and ready, shows the status of both, checks the pool's HA settings, and
   offers to set `ha-host-failures-to-tolerate=1` if it is not.
9. **Operating rules,** printed from Vates' pages: HA stays on for one-host work
   that comes back at the same version, goes off for updates and anything that
   touches both hosts, hosts are not renamed after setup, and a VM with PCI
   passthrough must not be HA-protected.

## Updating

**Update** (or `--twinstor-upgrade`) puts the pinned bundle on the hosts one at a
time, as Vates' Updates page asks, and never both at once:

1. It prints the notes that apply to the jump from the installed version to the
   pinned one (for example, that a 0.6.x to 0.7.x upgrade must be done on both
   hosts back to back, with no network work in between).
2. For each host, non-master first so the connection the script uses goes last: it
   downloads and verifies the bundle and runs `install.sh`, runs
   `twinstor upgrade-apply --check` (which exits non-zero if a restart is not
   safe right now, and stops the run if so), then `twinstor upgrade-apply --yes`.
3. It waits up to 30 minutes for that host to report healthy and ready before it
   touches the next one.

Guests keep running. XCP-ng host updates are not part of this: use a Rolling Pool
Update with HA off, as Vates describes.

## Machine requirements

On the machine running the script: `ssh`, `ssh-keygen` and `ssh-keyscan`. `sshpass`
is optional (without it ssh asks for the password again), and is needed only to
join a second host to a one-host pool. On the pool's hosts: `wget`, which XCP-ng
has.

## Not in the menu

The menu is Install, Update, Status and Support bundle. These Vates commands are
not wrapped; run them on the host yourself when Vates' pages or an alert say so:

| To do this | Run on the host |
| --- | --- |
| Replace a failed data disk | `twinstor replace-backing <new-device-by-id>` (starts a full resync; run VMs on the healthy host meanwhile) |
| Move replication back to the direct cable (arbitrated, after a `twinstor_replication_fallback` alert) | `twinstor failback-replication` |
| Clear a `config:` line in `twinstor status` | `twinstor regenerate-config --persist-only --yes` in a maintenance window, then restart that host, wait for `ready`, and do the other |
| Remove TwinStor | `twinstor uninstall` (add `--keep-data` to keep the data device). It refuses while VMs still use the SR |
| Check the configuration and get fixes | `twinstor doctor` (Status already runs it) |

## The bundle pin

```
TWINSTOR_VERSION=0.7.4
TWINSTOR_SHA256=0122a43a1b07bb253a33e5ec1b947a0eb9490ecbc83347585eeed804c20679f4
```

Both have defaults in the script and are documented in `sample-xo-config.cfg`. For
a newer build, copy the version and SHA-256 from Vates' deployment page. The
download URL is built from the version
(`https://github.com/vatesfr/twinstor/releases/download/v<version>/twinstor-test-<version>.tar.gz`).
Both values are checked for shape before they are used in a command on a host.

## What has not been tested

This was written from Vates' pages and the 0.7.4 bundle itself (its `install.sh`,
and the help and messages of its `twinstor` binary, run in a container), and
checked with unit tests that fake the pool and the hosts. It has **not been run
against real hosts**. Two things rest on reading rather than on seeing them
work: that the first host prints `Action required` once it is waiting for the
second, which is how the script knows when to start the second host, and the
disk and partition filter, which follows setup's own refusal reasons but cannot
see what XAPI knows about a local SR. `twinstor setup` still has the last word:
it refuses a device it will not use, and the script never passes `--force-device`.
Please report what a real run does.
