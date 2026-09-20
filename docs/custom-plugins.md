# Custom Plugins (`--custom-plugins`)

[← back to the README](../README.md)

Xen Orchestra has its own plugin system: a plugin is a `xo-server-*` npm
package that `xo-server` discovers automatically (from `/usr/local/lib/
node_modules`, among other places) and exposes for configuration under
**Settings > Plugins** in XO's own web UI. This project ships a small,
growing set of such plugins in [`plugins/`](../plugins) — this is **not**
XO's own official plugin catalogue, and none of this touches XO's web UI
(`xo-web`) itself.

`--custom-plugins` (or the **Custom Plugins** entry in the interactive menu)
installs them onto an already-running XO. It is a separate, opt-in step —
`--install` never installs any of these on its own.

```bash
./install-xen-orchestra.sh --custom-plugins
```

You'll be shown what's available and asked which to install (or pass
`--non-interactive` to install all of them) — from the interactive menu,
pressing `q` here backs out to the main menu without changing anything,
rather than quitting the script. Each one is copied to
`/usr/local/lib/node_modules/<plugin-name>` — a location `xo-server` already
scans by default and which `--update`'s `git pull`/rebuild never touches —
then `xo-server` is restarted so it picks them up. Configuration itself
happens afterwards, in XO: **Settings > Plugins**.

## What's available

### `xo-server-nanokvm`

Lets other plugins power a host on through a [Sipeed
NanoKVM](https://wiki.sipeed.com/nanokvm) device wired to that host's
power/reset header. Configure one entry per NanoKVM device: its URL, a
NanoKVM account, and which XO host UUID it controls. Use a dedicated
`user`-role account (**Settings > Account**, needs firmware 2.5.1+) —
`user` already has power/reset access. On older firmware without multi-user
support, use the admin account instead.

This plugin does not use NanoKVM's MCP endpoint — that only exposes
keyboard/mouse/screenshot tools, not power control. It talks to NanoKVM's
own REST API instead (the same one its web UI uses).

See [`plugins/xo-server-nanokvm/README.md`](../plugins/xo-server-nanokvm/README.md)
for the full configuration reference.

### `xo-server-host-power-manager`

Powers an extra pool host on when the rest of the pool is short on CPU or
memory, and powers it back off (evacuating VMs first) once it isn't needed.
Per managed host, you choose:

- A CPU trigger: average utilization % **or** vCPU:pCPU ratio. Optional —
  its Metric defaults to `Not used`; pick a metric and fill in both
  thresholds to turn it on.
- A memory trigger: free memory % **or** free memory in GB. Optional, same
  `Not used` default. At least one of the two triggers must be configured.
- Which provider powers it back **on**: XO's own built-in host power-on
  (iLO/DRAC/Wake-on-LAN — whatever's already set on the host under **Host >
  Advanced**), or `xo-server-nanokvm` for hosts that only have a NanoKVM.

Power-**off** always goes through XO's own `Host.shutdown`, regardless of
provider — never NanoKVM or IPMI. It evacuates running VMs first (the same
path as XO's "enable maintenance mode") and cleanly powers off standard
hardware. If the pool has HA enabled and this would break its failover
plan, XAPI refuses the power-off and the plugin logs why, rather than
forcing it through. Power-on reacts immediately (either resource being
tight is reason enough); power-off requires both to be comfortable
continuously for a configurable cooldown, so a brief dip doesn't cause
flapping.

See
[`plugins/xo-server-host-power-manager/README.md`](../plugins/xo-server-host-power-manager/README.md)
for the full configuration reference.

## Updating or uninstalling one

Run `--custom-plugins` (or the menu entry) again — already-installed plugins
show up pre-checked. Uncheck one and confirm to remove it; check a new one
to install it; leave an already-checked one checked to refresh it from this
repo's current checkout, if it's changed since it was installed (nothing
happens if it hasn't). All three can be done in the same pass.

This is also how an already-live plugin picks up a newer version later: pull
this repo, then run `--custom-plugins` again and leave it checked. Custom
plugins live outside `/opt/xen-orchestra` specifically so `--update`'s XO
rebuild never touches them, and for the same reason `--update` doesn't touch
them either — refreshing a plugin is a separate, explicit step, same as
installing one.

A plugin's configuration stays in XO's own database (Redis) until you also
remove it from **Settings > Plugins** — uninstalling or updating here never
touches it.
