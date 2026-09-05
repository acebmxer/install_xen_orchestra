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

Run it from your workstation. Like `--deploy`, it works over SSH against the
pool master and installs nothing locally — your Xen Orchestra installation is
not touched.

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
and 26.04, whose images expand to more than the default would hold. They are
starting points, pre-filled in XO's New VM form, not limits.

## Available templates

| Template | Image | Default login |
| --- | --- | --- |
| Debian 12 (Bookworm) | `debian-12-generic-amd64.raw` from `cloud.debian.org` | `debian` |
| Debian 13 (Trixie) | `debian-13-generic-amd64.raw` from `cloud.debian.org` | `debian` |
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

## Coming soon

These appear in the menu marked **Coming Soon...** and cannot be selected. They
are listed rather than left out so the catalogue answers "will my distribution
be here?" without anyone reading the source. Each one names a real published
cloud image — the URLs were checked, and each returns a live image with a
published checksum beside it — so what is missing is the code, not the image.

| Template | Image origin |
| --- | --- |
| AlmaLinux 8 / 9 / 10 | `repo.almalinux.org` |
| CentOS Stream 9 / 10 | `cloud.centos.org` |
| Fedora 43 / 44 | `dl.fedoraproject.org` |
| Rocky Linux 8 / 9 / 10 | `dl.rockylinux.org` |

Three things stood between these and a working entry. The first two are now
solved for every image rather than per-distribution, which is what made the
Ubuntu entries buildable and leaves only the RHEL family here:

1. **Image format.** ~~Debian publishes `raw`; everyone else publishes
   `qcow2`.~~ **Solved.** A non-raw image is now converted to raw with
   `qemu-img` on the pool master before the import. This needs the staged path,
   since there is nothing to convert in a stream, so a qcow2 image cannot fall
   back to streaming when `/var/tmp` is short on space.
2. **Checksum format.** ~~The verification reads Debian's `SHA512SUMS`.~~
   **Solved for Ubuntu.** The checksum file and algorithm are now chosen from
   the image's own URL: Debian's `SHA512SUMS` and Ubuntu's `SHA256SUMS` are
   both in coreutils' `<hash>  <file>` shape, so one parse serves both. The
   RHEL family and Fedora publish `SHA256 (file) = hash`, a different format
   that is still unhandled — part of why those entries remain here.
3. **Guest preparation.** The preparation script is `apt`-based, and Ubuntu
   shares it. The RHEL family and Fedora still need a `dnf` equivalent, and
   that is now the main thing between them and a working entry.

Adding a distribution beyond these is additive — the catalogue is a table of
one row per entry and the build loops over it.

Images come from the distribution's own mirror, so nothing is redistributed and
you can see exactly what you are installing. Checksums are not pinned in the
script: every origin publishes a checksum file beside its image — `SHA512SUMS`
for Debian, `SHA256SUMS` for Ubuntu — which is fetched and verified at build
time, so a new upstream release is picked up without anyone editing the
catalogue. Which file and which algorithm is worked out from the image's URL,
so adding an image does not mean declaring its checksum format alongside it.

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
   identity a clone must not inherit — machine-id, SSH host keys, cloud-init
   state, logs and shell history — and powers the VM off. This is the slow part;
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

  **The Ubuntu templates need more, and cannot fall back to streaming.** A
  qcow2 has to be downloaded and then converted, so both files exist at once:
  allow around 4.5 GB. Streaming is not an option for it because there is nothing to convert
  in a pipe, so a pool master short on `/var/tmp` fails the build with a
  message saying so rather than importing something that will not boot.

- `qemu-img` on the pool master, for any template whose image is not raw —
  currently the Ubuntu ones. XCP-ng does not always ship it, so the build checks
  before downloading anything and offers to install it from XCP-ng's own base
  repository (`yum install --enablerepo=base -y qemu-img`). Decline and the
  build stops without having downloaded the image.
- `guest-tools.iso` must be present on the pool. It normally lives in the
  **XCP-ng Tools** storage repository. A build stops if it is missing rather
  than producing a template whose VMs never report an IP.
- `genisoimage` or `xorriso` on your workstation, to build the preparation
  drive. If neither is present the script offers to install `xorriso`, which is
  packaged on both Debian and RHEL families.

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
