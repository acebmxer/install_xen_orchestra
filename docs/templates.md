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
  the password set to the same word (`debian` / `debian` for Debian 13). This
  matches how the equivalent Hub templates behave. Supply
  `ssh_authorized_keys` at creation and lock the password afterwards if you
  would rather not have one.
- **Boot firmware chosen from the image.** After the build, the imported disk's
  partition table is read: if it carries an EFI system partition the template is
  published as UEFI, otherwise as BIOS. The Debian images carry an ESP *and* a
  BIOS boot partition, so either choice works from XO's "Boot firmware"
  dropdown — the template just gives you the right default.

Defaults are 2 vCPUs, 2 GiB of RAM and a 4 GiB disk. They are starting points,
pre-filled in XO's New VM form, not limits.

## Available templates

| Template | Image | Default login |
| --- | --- | --- |
| Debian 13 (Trixie) | `debian-13-generic-amd64.raw` from `cloud.debian.org` | `debian` |

Debian 13 is the first entry, not the intended limit — the catalogue is a table
of one row per distribution and further ones are additive, needing no change to
the build itself.

Images come from the distribution's own mirror, so nothing is redistributed and
you can see exactly what you are installing. Checksums are not pinned in the
script: every origin publishes a `SHA512SUMS` beside its image, which is fetched
and verified at build time, so a new upstream release is picked up without
anyone editing the catalogue.

## What a build does

1. **Creates a build VM** from the pool's `Other install media` template and a
   disk sized for the image.
2. **Downloads the cloud image to the pool master** and verifies it against the
   origin's published `SHA512SUMS`. The download runs on the pool master, so the
   3 GB never crosses your workstation's link.
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
  `/var/tmp` to stage the image — roughly 3.3 GB. If it is short, the build
  streams the image straight into the disk instead, which cannot resume a
  broken transfer.
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
