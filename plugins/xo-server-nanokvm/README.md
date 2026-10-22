# xo-server-nanokvm

Xen Orchestra plugin that lets other plugins power on a host through a
[Sipeed NanoKVM](https://wiki.sipeed.com/nanokvm) device wired to that host's
power/reset header. It does not decide *when* to power a host on — see
[xo-server-host-power-manager](../xo-server-host-power-manager) for that.

It talks directly to NanoKVM's own REST API (`/api/auth/login` and
`/api/vm/gpio`), the same interface NanoKVM's web UI uses. It does **not**
use NanoKVM's MCP endpoint — that only exposes keyboard/mouse/screenshot
tools, not power control.

## Install

Copy this folder to `/usr/local/lib/node_modules/xo-server-nanokvm` on the
XO server (this is one of `xo-server`'s default plugin lookup paths, so it
survives `--update`), then restart `xo-server`. If you're using
[install_xen_orchestra](https://github.com/acebmxer/install_xen_orchestra),
its Custom Plugins menu does this for you automatically.

## Configure

In XO: **Settings > Plugins > nanokvm**. Add one entry to **NanoKVM devices**
per host that has a NanoKVM attached:

| Field | Meaning |
| --- | --- |
| Label | Free-text name shown in logs, e.g. `host NanoKVM` |
| Base URL | e.g. `https://host.example.com` |
| Username / Password | A NanoKVM account — see **Account** below |
| XO host UUID | The XCP-ng host this device's power header is wired to |

Devices can share the same username/password, or each use their own —
both work, since every entry is independent.

## HTTP or HTTPS

Use an `https://` Base URL where you can. With `http://`:

- the password is sent in a form anyone watching the network can decrypt.
  NanoKVM's login encrypts it with a passphrase that is the same on every
  device and published in NanoKVM's source, so it hides nothing;
- the session cookie the device hands back travels in clear, and whoever
  copies it can press the power button until it expires.

With `https://`, xo-server (Node.js) checks the device's certificate. The
one NanoKVM generates when you turn HTTPS on is self-signed and issued to
`localhost` only, so it is refused even if you tell Node to trust it: the
name never matches the Base URL. To use HTTPS:

1. Turn HTTPS on in NanoKVM's web UI first. Doing it later regenerates the
   certificate and overwrites yours.
2. Replace `/etc/kvm/server.crt` and `/etc/kvm/server.key` on the device
   with a certificate issued to the name (or IP address) in your Base URL,
   then restart the device.
3. If that certificate is not from a CA the XO server already trusts (for
   example you made it self-signed), tell xo-server to trust it by pointing
   `NODE_EXTRA_CA_CERTS` at a copy of it on the XO server, in a systemd
   drop-in:

   ```bash
   sudo systemctl edit xo-server
   ```

   ```ini
   [Service]
   Environment=NODE_EXTRA_CA_CERTS=/etc/ssl/nanokvm.pem
   ```

   then `sudo systemctl restart xo-server`.

Use the Test button to check it. If HTTPS is not an option, keep the NanoKVM
and the XO server on an isolated network that nothing else can reach, and use
`http://` there.

## Account

Create a dedicated account with the `user` role (**Settings > Account**),
rather than using `admin` — `user` already includes power/reset access, so
the plugin never needs to hold credentials that could also touch KVM
system/network/storage administration.

Multi-user support (separate `admin`/`user` roles) requires **NanoKVM
firmware 2.5.1 or later** — on older firmware there's only a single admin
account, in which case use that instead.

## Test button

The **Test** button on a device's config page logs in and reads the power
LED's GPIO state, without pressing anything — a way to check the URL and
credentials are correct before relying on it.

XO's own "Test plugin" dialog only ever shows a static "appears to be
working" message on success — it discards the actual result. To see the
power LED reading, check `sudo journalctl -u xo-server` right after
clicking Test; it's logged there.

## What it can't do

NanoKVM's power button toggles power: the same press switches a host on or
off. Before pressing it for a power-on, xo-server-host-power-manager reads
the power LED through this plugin and presses only when it reports off.
This plugin does not attempt to power a host *off*: XO's own
`Host.shutdown` already asks the OS to shut down cleanly (which physically
powers off standard hardware) and evacuates running VMs first — see
xo-server-host-power-manager, which uses that for every host regardless of
which power-on provider is configured.
