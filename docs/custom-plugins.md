# Custom Plugins (`--custom-plugins`)

[← back to the README](../README.md)

Xen Orchestra has its own plugin system: a plugin is a `xo-server-*` npm
package that `xo-server` discovers automatically (from `/usr/local/lib/
node_modules`, among other places) and exposes for configuration under
**Settings > Plugins** in XO's own web UI. This project ships a small,
growing set of such plugins in [`plugins/`](../plugins) — this is **not**
XO's own official plugin catalogue, and none of this touches XO's web UI
(`xo-web`) itself.

These plugins are also maintained standalone in
[github.com/acebmxer/xo-plugins](https://github.com/acebmxer/xo-plugins),
for anyone who wants them without the rest of this project — the two are
kept in sync.

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
forcing it through — that XAPI-side evacuation check, not this plugin's own
thresholds, is what actually guarantees a power-off won't strand VMs.
Power-on reacts immediately (either resource being tight is reason enough);
power-off requires both to be comfortable continuously for a configurable
cooldown, so a brief dip doesn't cause flapping.

CPU/memory thresholds are measured across every currently running host in
the pool, including the managed host itself while it's running — matching
XO's own pool dashboard.

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

## Keeping `xo-plugins` in sync

[xo-plugins](https://github.com/acebmxer/xo-plugins) has `dev` and `main`
branches mirroring this repo's own workflow, so unreleased plugin work
never reaches its `main` early. This repo is the source of truth for the
plugins; `xo-plugins` is kept identical to it.

CI keeps the two in sync automatically, in both directions, so nobody has
to remember to run anything by hand:

- A `plugins/<name>/` change pushed here (`sync-plugins-out.yml`) runs
  `scripts/plugin-push.sh <name>` for you, pushing it to `xo-plugins`.
- A change made directly in `xo-plugins` (its own `notify-install-repo.yml`)
  tells this repo (via `repository_dispatch`) to pull it back in
  (`sync-plugins-in.yml`, using `scripts/plugin-pull.sh <name>`) and commit
  it here.

Both directions only sync whichever branch (`dev`/`main`) changed, matching
that branch on the other side.

The two scripts still work the same when run by hand, for a one-off or if
CI can't reach the other repo:

- `scripts/plugin-push.sh <plugin-name>` — this repo → `xo-plugins`.
  Commits here only; run it after committing a plugin change.
- `scripts/plugin-pull.sh <plugin-name>` — `xo-plugins` → this repo. Copies
  files over `plugins/<plugin-name>/` but doesn't commit; review and commit
  yourself.

Both refuse to run from any branch other than `dev`/`main`.

**Adding a new plugin:** put it in `plugins/<name>/` here as usual, then
one-time import it into `xo-plugins` (once per branch, `dev` and `main`):

```bash
git subtree split --prefix=plugins/<name> -b tmp-import-<name>
git clone https://github.com/acebmxer/xo-plugins.git /tmp/xo-plugins-import
cd /tmp/xo-plugins-import
git checkout <dev-or-main>
git remote add source /home/nick/Projects/github/install_xen_orchestra
git fetch source tmp-import-<name>
git subtree add --prefix=<name> source tmp-import-<name> -m "Import <name>"
git push origin <dev-or-main>
cd -; git branch -D tmp-import-<name>; rm -rf /tmp/xo-plugins-import
```

After that, `plugin-push.sh`/`plugin-pull.sh` work the same as for the
existing plugins — nothing plugin-specific about them.
