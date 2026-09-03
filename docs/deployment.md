# Deploying to a new VM (`--deploy`)

[← back to the README](../README.md)

If you don't already have a Linux VM to install into, `--deploy` builds one for
you. Run it **from your own workstation** — it is the only operation in this
script that does not run on the machine Xen Orchestra ends up on:

```bash
git clone https://github.com/acebmxer/install_xen_orchestra.git
cd install_xen_orchestra
./install-xen-orchestra.sh --deploy
```

It will ask for your pool master's address and root password, let you pick a
storage repository and network from what the pool actually has, then ask for
the VM's size, admin account (with a required password), where to clone this
repository inside the guest, and its static address. From there it:

1. Creates the VM and streams a stock **Debian 13 cloud image** from
   `cloud.debian.org` straight into its disk. The download runs *on the pool
   master*, so the 3 GB never crosses your workstation's link and never lands
   on dom0's root filesystem.
2. Attaches a cloud-init config drive that creates your admin user, installs a
   freshly generated SSH key, applies the static address, and clones this
   repository into the guest — either `/opt/install_xen_orchestra` or
   `/home/<admin>/install_xen_orchestra`, whichever you pick.
3. SSHes in and runs `--install --non-interactive`, streaming the output to
   your terminal so you see the build as it happens.
4. Verifies XO answers on `/signin`, then detaches and destroys the cloud-init
   config drive — it has served its purpose, and it holds the admin password
   hash. If the guest refuses the hot-unplug, you get the `xe` commands to
   remove it by hand rather than a failed deploy.

**Changing settings the prompts don't cover**

`--deploy` only asks about the HTTP/HTTPS ports and the git branch. Everything
else the VM is installed with — `INSTALL_DIR`, `SERVICE_USER`, `NODE_VERSION`,
SSL and backup paths — comes from a base config, and you get to see it before
anything is created on the pool:

- The base is `sample-xo-config.cfg` from the repo. If you also keep an
  `xo-config.cfg` beside the script, you are asked which of the two the VM
  should start from. (Check its paths first — they were written for whatever
  machine it came from, not a fresh Debian VM.)
- Right after the prompts, `--deploy` offers to open the generated config in
  your editor (`$EDITOR`/`$VISUAL`, else the base config's `PREFERRED_EDITOR`,
  else nano/vim/vi — including one with arguments, such as `code --wait`).
  Save and quit and the VM is built with exactly what you left there.

The edit happens on a throwaway copy in a temp directory, so neither the
tracked sample nor your own `xo-config.cfg` is modified. Changing the ports in
the editor is picked up too — the review screen, the post-install check and the
summary all follow what the file ends up saying. If the file comes back with a
port or branch the install could not use, the problem is named and the editor
reopens; nothing has been created on the pool at that point.

**Requirements**

- The pool master must have outbound internet access.
- A free **static IP** — this is required, not optional. A stock Debian cloud
  image has no `xe-guest-utilities`, so the host cannot report a DHCP lease
  back and the script would have no address to install over.
- On your workstation: `ssh`, `scp`, `ssh-keygen`, and an ISO writer
  (`genisoimage` or `xorriso`). Only the ISO writer might need installing, and
  that is the sole reason `--deploy` would ask for sudo — nothing else about
  this operation touches your machine. `sshpass` is optional: with it you are
  asked for the pool master password once, without it `ssh` asks a second time.

**Afterwards** the VM contains an ordinary checkout of this repository, so
updates work there exactly as anywhere else:

```bash
ssh -i xo-deploy-<hostname>.key <admin>@<ip>
cd <clone dir> && ./install-xen-orchestra.sh --update
```

The generated SSH private key is saved next to the script as
`xo-deploy-<hostname>.key` (git-ignored). Keep it, or add your own key to the VM
and delete it. Deploying a second VM with a hostname you have used before does
not overwrite the first key — that file is the only way into that machine — so
the new one is saved as `xo-deploy-<hostname>-2.key` and the summary tells you
which key belongs to the VM just built.

The VM clones this repository from whatever `origin` your checkout uses, so a
fork deploys itself. An SSH remote (`git@github.com:...`) is converted to the
equivalent HTTPS URL first, since the VM has none of your keys, and any
credentials embedded in an HTTPS remote are stripped rather than copied into
the guest's cloud-init data. The URL the VM will actually use is shown on the
review screen before anything is created.

**The admin account's password is required.** It is asked for during the
prompts and there is no way to skip it, because it is the credential the
finished VM is left with: the console login in XO Lite or XCP-ng Center where
no key can be offered, what `su` asks for, and what `sudo` asks for once the
deploy finishes. The minimum is 12 characters. A second prompt asks whether SSH
should accept the password too; the default is no. Hashing it needs `openssl`
(or `mkpasswd`) on your workstation — without either, the deploy stops rather
than quietly creating an account you cannot log in to.

For `--non-interactive`, supply it as `XO_DEPLOY_ADMIN_PASSWORD` (and
optionally `XO_DEPLOY_ADMIN_SSH_PWAUTH=true`). The deploy refuses to run
without it.

**SSH access uses your own key, not one this script leaves lying around.** The
deploy generates a temporary keypair because the unattended install has to
reach the guest somehow, but that key is a deployment credential, not a login:

- the private half is written only to a mode-700 temporary directory and is
  shredded and deleted when the run ends — it is never saved next to the
  script;
- its public half is removed from the VM's `authorized_keys` as the last step
  of the deploy, and the removal is *verified* by attempting a connection that
  must now fail.

So when the deploy is over, that key opens nothing. To keep SSH access, give
the deploy a public key of your own at the prompt — it offers
`~/.ssh/id_ed25519.pub` (or your ECDSA/RSA equivalent) if you have one, and
accepts any path. Press Enter to take the offered key, or type `-` for none.
Under `--non-interactive`, set `XO_DEPLOY_ADMIN_SSH_KEY` to a path or to the
key text itself.

Declining a key is supported and is the most locked-down outcome: the account
still has its password for the console, and for SSH too if you enabled password
logins. If you enabled neither, the console is the only way in — the summary
says so plainly, and tells you how to add a key afterwards.

> [!NOTE]
> Only public keys are accepted. Handing it a *private* key by mistake is
> rejected rather than embedded into the VM's cloud-init data, where it would
> be readable by anyone on the guest.

The VM is created with `SERVICE_USER=root` (the current default) and XO's
usual `admin@admin.net` / `admin` starting credentials — **changing that login
is highly recommended before putting the VM to use.** See
[Default Credentials](../README.md#default-credentials) for why this one matters more than
a typical default password.

**What the deploy hardens on its way out.** The unattended install needs
passwordless `sudo` in the guest — it runs over SSH with no terminal to answer
a password prompt — so cloud-init grants `ALL=(ALL) NOPASSWD:ALL` while it
runs. That grant is revoked when the install finishes: the rule is rewritten to
the ordinary `ALL=(ALL:ALL) ALL`, validated with `visudo` before and after, and
rolled back automatically if the resulting sudoers tree does not parse. The
summary tells you which mode the VM ended up in.

Because the admin password is now mandatory, there is always a password for
`sudo` to ask for and this step always runs. (The guard that skips it for a
passwordless account is still in the code — requiring a password from an
account that has none would lock you out of root rather than harden anything —
but a normal deploy no longer reaches it.)

The deploy also brings the guest up to its distribution's current security
patches on first boot (the stock cloud image is only patched to its build date)
and installs `unattended-upgrades` so it stays that way. Once the install is
done, the cloud-init config drive is detached and destroyed, and the copies of
the user-data that cloud-init cached inside the guest — which hold the admin
password hash — are redacted along with any occurrence in its logs.

> [!NOTE]
> Earlier versions saved the deployment key as `xo-deploy-<hostname>.key` next
> to the script. They no longer do, and any such file left over from a previous
> run is a passphraseless private key granting root-equivalent access to that
> VM. Remove its line from that VM's `~/.ssh/authorized_keys` and delete the
> file.

**Verifying the pool master.** The host password you type is sent to the pool
master over SSH, so on the first connection to a host that is not yet in your
`known_hosts`, the script shows the host key fingerprint and asks you to
confirm it against `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the
host's console. Once the key is known, `ssh` enforces it and no prompt appears.
For unattended runs, set `XO_DEPLOY_POOL_FINGERPRINT` to the expected SHA256
fingerprint and the deploy verifies it instead of prompting, aborting before
the password is sent if it does not match.

To deploy a different Debian release, set `XO_DEPLOY_IMAGE_VERSION` and
`XO_DEPLOY_IMAGE_RELEASE`, or point `XO_DEPLOY_IMAGE_URL` at any raw cloud
image with cloud-init installed.

The staged image is checked against the `SHA512SUMS` its origin publishes
alongside it, which is what Debian ships. A mismatch always aborts the deploy.
An origin that publishes no sums — a private mirror, say — warns and continues,
so pointing `XO_DEPLOY_IMAGE_URL` somewhere custom keeps working.

Set `XO_DEPLOY_IMAGE_SHA512` to require a specific digest instead. Like
`XO_DEPLOY_POOL_FINGERPRINT`, this makes the check mandatory: if it cannot be
performed the deploy stops rather than continuing unverified. That also rules
out the streaming import, which feeds the origin straight into the disk with no
file to hash — so a host too short on scratch space to stage the image will
refuse rather than import something it cannot check.

Note that fetching the sums over the same connection as the image is not a
detached signature. It defends against a bad mirror or a stale cache, not
against an attacker who holds the TLS session for both requests. Pin the digest
when that distinction matters to you.

## Checking a host before deploying

`--deploy` depends on XAPI behaviour that the test suite cannot exercise
without a hypervisor. If a deploy fails, or you want to check a host first,
run the probe:

```bash
./tests/probe-xapi-deploy.sh --host 192.168.1.10
```

It verifies each assumption in turn — SR and network enumeration, the pool
master's internet access, `vdi-import` from a pipe (round-tripped and
checksummed, not just exit-code checked), the `/import_raw_vdi` HTTP fallback,
and VM creation with the boot and memory parameters deploy sets. Everything it
creates is named `xo-probe-<run id>` and destroyed on exit, including on
failure; it never touches objects it did not create, and never starts a VM.

