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
survives `--update`), then restart `xo-server`. The Custom Plugins entry in
`install-xen-orchestra.sh`'s menu does this for you.

## Configure

In XO: **Settings > Plugins > nanokvm**. Add one entry to **NanoKVM devices**
per host that has a NanoKVM attached:

| Field | Meaning |
| --- | --- |
| Label | Free-text name shown in logs, e.g. `host3 NanoKVM` |
| Base URL | e.g. `https://host3.pozzatech.com` |
| Username / Password | A NanoKVM account — see **Account** below |
| XO host UUID | The XCP-ng host this device's power header is wired to |

Devices can share the same username/password, or each use their own —
both work, since every entry is independent.

## Account

Create a dedicated account with the `user` role (**Settings > Account**),
rather than using `admin` — `user` already includes power/reset access, so
the plugin never needs to hold credentials that could also touch KVM
system/network/storage administration.

Multi-user support (separate `admin`/`user` roles) requires **NanoKVM
firmware 2.5.1 or later** — on older firmware there's only a single admin
account, in which case use that instead.

## What it can't do

NanoKVM only knows how to press a button — it can't tell "host is off" from
"host is on". Power-on works because the caller already knows the host is
off. This plugin does not attempt to power a host *off*: XO's own
`Host.shutdown` already asks the OS to shut down cleanly (which physically
powers off standard hardware) and evacuates running VMs first — see
xo-server-host-power-manager, which uses that for every host regardless of
which power-on provider is configured.
