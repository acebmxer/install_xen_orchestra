# Building VM templates (`--build-templates`)

[← back to the README](../README.md)

Xen Orchestra's Hub — the catalogue of ready-to-deploy Linux templates — does
not work on an install from sources. The gate is not the plan check in the web
client but the `cloud.*` API behind it: `xo-web` calls
`cloud.getResourceCatalog` and `cloud.downloadAndInstallResource`, and neither
has an implementation anywhere in the open-source tree. The package that
provides them is not among those published, so there is nothing to unlock.

`--build-templates` builds the equivalent on your pool instead, from each
distribution's own published cloud image:

```bash
./install-xen-orchestra.sh --build-templates
```

It is also the **VM Template Library** entry in the interactive menu.

Run it from your workstation — Debian, Ubuntu, Fedora, Arch, CachyOS, openSUSE
or anything with `apt`, `dnf`, `pacman`, `zypper` or `apk`. It talks to XO's API
(or falls back to SSH against the pool master) and does not touch your Xen
Orchestra installation. The few tools it needs on that machine — `xo-cli`,
`qemu-img`, and an ISO writer for the SSH path — it checks for up front and
offers to install with your package manager; nothing is installed without a
prompt.

## What you get

A sealed VM template that appears in Xen Orchestra under **New → VM**, sitting
alongside any Hub templates you already have. Set the name, CPU, memory, disk
size and network there; cloud-init's growpart expands the filesystem to
whatever disk size you ask for on first boot.

Each template ships with:

- **cloud-init**, so you can supply an SSH key or a full cloud-config at VM
  creation time.
- **XCP-ng guest tools**, installed from `guest-tools.iso` on the pool. Without
  these XO never reports a VM's IP address, so a build fails rather than
  producing a template that looks fine and is quietly useless.
- **A shipped login** — the account named in the template's description, with
  the password set to the same word (`debian` / `debian` for the Debian
  templates, `ubuntu` / `ubuntu` for the Ubuntu ones). This matches how the
  equivalent Hub templates behave. Supply
  `ssh_authorized_keys` at creation and lock the password afterwards if you
  would rather not have one.
- **Boot firmware chosen from the image.** After the build, the imported disk's
  partition table is read: if it carries an EFI system partition the template is
  published as UEFI, otherwise as BIOS. The Debian and Ubuntu images all carry
  an ESP *and* a BIOS boot partition, so either choice works from XO's "Boot
  firmware" dropdown — the template just gives you the right default.

Defaults are 2 vCPUs, 2 GiB of RAM and a 4 GiB disk — 6 GiB for Ubuntu 24.04
and 26.04, 5 GiB for the Fedora entries, and 10 GiB for the AlmaLinux, CentOS
Stream and Rocky Linux entries, whose images expand to more than the default
would hold. They are starting points, pre-filled in XO's New VM form, not
limits.

## Available templates

| Template | Image | Default login |
| --- | --- | --- |
| AlmaLinux 8 | `AlmaLinux-8-GenericCloud-latest.x86_64.qcow2` from `repo.almalinux.org` | `almalinux` |
| AlmaLinux 9 | `AlmaLinux-9-GenericCloud-latest.x86_64.qcow2` from `repo.almalinux.org` | `almalinux` |
| AlmaLinux 10 | `AlmaLinux-10-GenericCloud-latest.x86_64.qcow2` from `repo.almalinux.org` | `almalinux` |
| CentOS Stream 9 | `CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2` from `cloud.centos.org` | `cloud-user` |
| CentOS Stream 10 | `CentOS-Stream-GenericCloud-10-latest.x86_64.qcow2` from `cloud.centos.org` | `cloud-user` |
| Debian 12 (Bookworm) | `debian-12-generic-amd64.raw` from `cloud.debian.org` | `debian` |
| Debian 13 (Trixie) | `debian-13-generic-amd64.raw` from `cloud.debian.org` | `debian` |
| Fedora 43 | `Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2` from `dl.fedoraproject.org` | `fedora` |
| Fedora 44 | `Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2` from `dl.fedoraproject.org` | `fedora` |
| Rocky Linux 8 | `Rocky-8-GenericCloud-Base.latest.x86_64.qcow2` from `dl.rockylinux.org` | `rocky` |
| Rocky Linux 9 | `Rocky-9-GenericCloud-Base.latest.x86_64.qcow2` from `dl.rockylinux.org` | `rocky` |
| Rocky Linux 10 | `Rocky-10-GenericCloud-Base.latest.x86_64.qcow2` from `dl.rockylinux.org` | `rocky` |
| Ubuntu 22.04 LTS (Jammy) | `jammy-server-cloudimg-amd64.img` from `cloud-images.ubuntu.com` | `ubuntu` |
| Ubuntu 24.04 LTS (Noble) | `noble-server-cloudimg-amd64.img` from `cloud-images.ubuntu.com` | `ubuntu` |
| Ubuntu 26.04 LTS (Resolute) | `resolute-server-cloudimg-amd64.img` from `cloud-images.ubuntu.com` | `ubuntu` |

The two Debian entries are built by the same code path from the same `generic`
image family; they differ only in the release they pull.

The three Ubuntu LTS entries use that same code path and the same in-guest
preparation script — Ubuntu packages `xe-guest-utilities`, so the guest tools
install from the ISO with a working `apt` fallback behind it. Two things differ
from Debian and are handled automatically:

- **The image is qcow2**, despite its `.img` name, so it is converted to raw on
  the pool master before the import. That needs `qemu-img` there; if it is
  missing the build offers to install it (see [Requirements](#requirements)).
- **They expand to larger disks than they download as.** 24.04 and 26.04 both
  become 3.5 GiB disks (from 596 MiB and 823 MiB downloads), so those two are
  built with a 6 GiB disk rather than the 4 GiB default. 22.04 expands to only
  2.2 GiB and keeps the default. The size is judged per image rather than per
  distribution. As with every template this is a starting point — set whatever
  size you want in XO's New VM form and cloud-init grows the filesystem to fit.

Ubuntu 22.04's free security maintenance ends on 2027-04-30, and this entry is
scheduled to be removed on **2027-06-01**. It is buildable until then.

The three AlmaLinux entries, both CentOS Stream entries and the three Rocky Linux
entries share a preparation script of their own — `tpl_prep_rhel`, the `dnf`
counterpart to the `apt` one Debian and Ubuntu use. It is named for the family
rather than for any one distribution. Five things differ from the Debian path:

- **Guest tools come from the ISO, with no package fallback attempted.**
  AlmaLinux 8, 9 and 10 and CentOS Stream 9 and 10 package `xe-guest-utilities`
  nowhere — checked against their base repositories and EPEL. Rocky Linux's EPEL
  does carry `xe-guest-utilities-latest`, but the script installs from the ISO
  for every row rather than branching per distribution, so no template depends
  on it. If the ISO is not attached the build fails rather than producing a
  template that never reports an IP.
- **SELinux is enforcing.** The script touches `/.autorelabel` so the files it
  writes are relabelled on first boot; without it an unlabelled sshd drop-in can
  leave a clone refusing logins with nothing obvious in the log.
- **Password login is enabled differently per release.** AlmaLinux 8 and
  Rocky Linux 8 ship neither `/etc/ssh/sshd_config.d` nor the `Include` line
  that reads it, so a drop-in alone would be silently ignored there; AlmaLinux
  9 and 10, both CentOS Stream releases and Rocky Linux 9 and 10 ship both. The
  script tests for a working include and edits `sshd_config` directly when
  there is none.
- **NetworkManager connections are removed.** This family bakes the build VM's
  MAC and DHCP client-id into a saved connection, which every clone would
  otherwise inherit and reuse.
- **The default user is unlocked.** These images declare `lock_passwd: True`,
  and cloud-init re-locks that account on every boot, so setting a password
  during the build is not enough on its own — see the note below.

The eight AlmaLinux, CentOS Stream and Rocky Linux entries are built with a
10 GiB disk rather than the 4 GiB default. Every one of those images is a 10 GiB
virtual disk however small the download is — AlmaLinux 8 downloads as 1.55 GiB
and AlmaLinux 10 as 0.48 GiB, CentOS Stream 9 as 1.19 GiB and 10 as 1.00 GiB,
Rocky Linux 8 as 1.92 GiB and 9 and 10 as roughly 0.6 GiB each, and all of them
expand to the same 10 GiB. AlmaLinux 8 and Rocky Linux 8 are supported until
2029-05-31, and both ship an image frozen at the final 8.10 point release —
which is not the same thing as the distribution approaching end of life.

Both Fedora entries are the exception to that figure: each expands to a 5 GiB
disk, so both are built with 5 GiB. The size is read off each image's own
`qemu-img info` "virtual size" rather than assumed from the family.

Both Fedora entries share a preparation script of their own,
`tpl_prep_fedora`, rather than the RHEL one. Fedora 44 was read the same way as
43 rather than assumed to match it — same default user, same `lock_passwd`,
same sshd `Include`, same 5 GiB image, and `xe-guest-utilities-latest` present
in its repositories too. Its partition table has three entries to 43's four,
carrying no separate `/boot`, which changes nothing: the build looks for the
ESP and never assumes a partition count. The rest of the work is the same, but the guest tools are
not: the ISO's `install.sh` recognises Debian, CentOS, RHEL, SLES and Ubuntu by
name and refuses anything else, and Fedora packages `xe-guest-utilities-latest`
in its own `updates` repository where the RHEL rebuilds take theirs from the
ISO. Keeping it separate means the eight rows already building on `tpl_prep_rhel`
are untouched.

Its guest-tools step follows the tiers `linux_util`'s installer already uses:

1. The ISO installer with the documented `-d fedora -m <release>` override,
   taken from the guest's own `/etc/os-release`, which is
   how [XCP-ng's documentation](https://docs.xcp-ng.org/vms/#linux-guest-tools)
   says to handle a distribution `install.sh` does not recognise.
2. Failing that, the `xe-guest-utilities_*_all.tgz` archive on the ISO,
   unpacked into `/etc` and `/usr` — the manual route the same page describes.
3. Failing that, Fedora's own package. Note the `-latest` suffix: a search for
   the bare name finds nothing on Fedora. XCP-ng's docs send Fedora to a
   package rather than the ISO for this reason, though they name EPEL, which
   has no Fedora branch — the package is in Fedora proper.

Each tier is confirmed by looking for `xe-daemon` on disk rather than trusting
an exit status, and the service is enabled and started after a package install
because the package does not enable it.

Fedora also needs its default user unlocking before the shipped password login
works. The image declares `lock_passwd: True` for that user and cloud-init
re-locks the account on every boot, so setting a password during the build is
not enough on its own — a clone comes up with it already locked. The build
writes `/etc/cloud/cloud.cfg.d/99-xo-template-login.cfg` with `lock_passwd:
False` and `ssh_pwauth: True`, which merges over the image's own block without
disturbing the username. **Delete that file once you have installed your own
SSH keys**, or supply `ssh_authorized_keys` at VM creation and never use the
password.

The same `lock_passwd: True` is present in the AlmaLinux, CentOS Stream and
Rocky Linux images, so `tpl_prep_rhel` writes the same drop-in for the same
reason. The `cloud.cfg.d` deep-merge was tested on cloud-init 23.4 (AlmaLinux 8,
and Rocky Linux 8, which ships the same) and 25.2 (Fedora); Rocky Linux 9 and 10
ship versions inside that span. Debian and Ubuntu need none of this — their
images do not lock the default user.

The CentOS Stream default account is `cloud-user`, not `centos`, Fedora's is
`fedora`, and Rocky Linux's is `rocky` — read out of each image's own
`/etc/cloud/cloud.cfg`, where `system_info.default_user.name` says so.

Fedora's root filesystem is btrfs with subvolumes, unlike every other entry
here. Nothing in the build reads the filesystem — the import is block-level and
growpart works on the partition — so it changes nothing in practice.

## Adding a distribution

Every distribution in the catalogue is buildable today — nothing is marked
**Coming Soon...**. Adding another is additive: the catalogue is one row per
entry and the build loops over it. The three things that once needed
per-distribution work are all solved generically:

1. **Image format.** Debian publishes `raw`; everyone else publishes `qcow2`. A
   non-raw image is converted to raw with `qemu-img` on the pool master before
   the import. This needs the staged path, since there is nothing to convert in
   a stream, so a qcow2 image cannot fall back to streaming when `/var/tmp` is
   short on space.
2. **Checksum format.** The checksum file and algorithm are chosen from the
   image's own URL, and the two shapes those files come in are both parsed:
   coreutils' `<hash>  <file>` (Debian's `SHA512SUMS`, Ubuntu's `SHA256SUMS`,
   AlmaLinux's `CHECKSUM`) and the BSD tag `SHA256 (<file>) = <hash>` (CentOS
   Stream's and Rocky Linux's `CHECKSUM`, all releases).

   The shape is not a property of the distribution family, which is why it is
   tried both ways rather than selected by origin: `repo.almalinux.org`,
   `cloud.centos.org` and `dl.rockylinux.org` all publish a file named
   `CHECKSUM` and do not agree on what goes inside it. Each carries an entry for
   the `.latest` / `-latest` filename this catalogue requests rather than only
   the dated name it points at.

   Fedora publishes the BSD shape too, but under a filename carrying the
   release and compose — `Fedora-Cloud-43-1.6-x86_64-CHECKSUM` — rather than a
   fixed name, so for that origin the filename is derived from the image's own
   name instead of being a constant. Its file is PGP clearsigned; the digest
   lines inside are ordinary BSD tag lines, so the parse reaches them, but the
   signature itself is not verified.
3. **Guest preparation.** `tpl_prep_rhel` is the `dnf` counterpart to
   `tpl_prep_debian` and serves the RHEL rebuilds — AlmaLinux, CentOS Stream
   and Rocky Linux, all releases. Both Fedora entries have their own,
   `tpl_prep_fedora`, because their guest tools do not come from the ISO the way
   the rebuilds' do.

A new row whose image has not been read yet can land with a `-` in its
prep-function field: the menu then shows it as **Coming Soon...** and refuses
to build it until the row is finished. Nothing uses that today.

Images come from the distribution's own mirror, so nothing is redistributed and
you can see exactly what you are installing. Checksums are not pinned in the
script: every origin publishes a checksum file beside its image — `SHA512SUMS`
for Debian, `SHA256SUMS` for Ubuntu, `CHECKSUM` for AlmaLinux, CentOS Stream and
Rocky Linux, and a release-stamped `Fedora-Cloud-<release>-<compose>-x86_64-CHECKSUM`
for Fedora — which is fetched and verified at build time, so a new upstream release
is picked up without anyone editing the catalogue. Which file and which algorithm
is worked out from the image's URL, so adding an image does not mean declaring
its checksum format alongside it.

## What a build does

1. **Creates a build VM** from the pool's `Other install media` template and a
   disk sized for the image.
2. **Downloads the cloud image to the pool master** and verifies it against the
   origin's published checksums. The download runs on the pool master, so the
   several gigabytes never cross your workstation's link. An image that is not
   raw — Ubuntu's `.img` files are qcow2 — is then converted to raw with
   `qemu-img`, after the checksum has been verified against the file as
   published.
3. **Imports it into the disk** over XAPI's HTTP endpoint, then confirms the
   disk actually holds a partition table before going further.
4. **Boots the VM once.** A cloud-init drive installs the guest tools, adds
   cloud-init and growroot, sets the shipped login, then scrubs the machine
   identity a clone must not inherit — machine-id, SSH host keys, hostname,
   saved network connections, cloud-init state, logs and shell history — and
   powers the VM off. This is the slow part;
   allow roughly five to ten minutes per template.
5. **Seals the result**: destroys the preparation drive so cloud-init does not
   find a used seed on every clone, ejects the tools ISO, sets the firmware and
   description, and flags the VM as a template.

Storage and network are not prompted for. The build uses the pool's default SR
(or the emptiest one, if no default is set) and the management network.

## Requirements

- The pool master must have outbound internet access, and enough space in
  `/var/tmp` to stage the image — roughly 3.3 GB for the Debian templates. If
  it is short, the build streams the image straight into the disk instead,
  which cannot resume a broken transfer.

  **Every template except the two Debian ones needs more on the SSH path, and
  cannot fall back to streaming.** Their images are qcow2 and have to be
  downloaded and then converted, so both files exist at once: allow around
  4.5 GB. Streaming is not an option because there is nothing to convert in a
  pipe, so a pool master short on `/var/tmp` fails the build with a message
  saying so rather than importing something that will not boot.

- **`qemu-img`, to convert those qcow2 images to raw** (XO's import endpoint
  takes raw and VHD only). Where it is needed depends on the build method:
  - **API path** — on your workstation, since that is where the image is
    downloaded. The build checks in its preflight and, if it is missing, offers
    to install it with your package manager (`qemu-utils` on Debian/Ubuntu,
    `qemu-tools` on openSUSE, `qemu-img` on the Fedora/RHEL and Arch families).
    Decline and the build uses the SSH path instead.
  - **SSH path** — on the pool master, where it is part of dom0 on any normal
    XCP-ng install. If it is somehow absent the build stops rather than
    installing anything onto dom0.
  A Debian-only selection needs `qemu-img` on neither: those images are raw.
- `guest-tools.iso` must be present on the pool. It normally lives in the
  **XCP-ng Tools** storage repository. A build stops if it is missing rather
  than producing a template whose VMs never report an IP.
- `genisoimage` or `xorriso` on your workstation (SSH path only — the API path
  has XO build the config drive). If neither is present the script offers to
  install `xorriso` with your package manager.

## If a build fails

The build VM is deliberately left in place, named `[building template] …`, so
you can look at it. The preparation script logs to
`/var/log/xo-template-prep.log` inside the guest.

Nothing is destroyed automatically — a failed build is yours to inspect and
remove:

```bash
xe vm-destroy uuid=<the uuid printed by the failure>
```

Building the same template again is safe: a template of the same name is
detected and skipped rather than duplicated, and the menu marks the ones your
pool already has. To rebuild one, delete the existing template in XO first.
