# xo-server-host-power-manager

Xen Orchestra plugin that powers an "extra" pool host on when the rest of
the pool is under CPU or memory pressure, and powers it back off once it
isn't needed anymore.

- **Power-on** goes through either XO's own built-in host power-on
  (iLO/DRAC/Wake-on-LAN — whatever's already configured on the host under
  **Host > Advanced**) or [xo-server-nanokvm](../xo-server-nanokvm), for
  hosts that only have a NanoKVM device. Pick per rule.
- **Power-off** always goes through XO's own `Host.shutdown`, regardless of
  provider — it evacuates any running VMs first, then shuts the host down
  cleanly (which physically powers off standard hardware).

## Install

Copy this folder to `/usr/local/lib/node_modules/xo-server-host-power-manager`
on the XO server, then restart `xo-server`. The Custom Plugins entry in
`install-xen-orchestra.sh`'s menu does this for you.

## Configure

In XO: **Settings > Plugins > host-power-manager**. Add one **rule** per
extra host:

| Field | Meaning |
| --- | --- |
| Extra host | The XO UUID of the host to manage |
| Power-on provider | `native` (iLO/DRAC/WoL) or `nanokvm` |
| CPU trigger | Metric (average % **or** vCPU:pCPU ratio) + power-on/power-off thresholds |
| Memory trigger | Metric (free % **or** free GB) + power-on/power-off thresholds |
| Poll interval | How often to re-check, in seconds (default 60) |
| Cooldown | Minutes; see **Behavior** below |

All metrics are computed from the pool's other **currently running**
hosts — the managed host's own (lack of) load never affects the decision to
power it on.

## Behavior

- **Power-on is immediate**: either CPU or memory crossing its threshold is
  enough — resources are additive, so one being tight is reason enough to
  add capacity.
- **Power-off requires both** CPU and memory to be comfortably under their
  thresholds, continuously, for the full cooldown period. This is
  deliberately asymmetric — scale up fast, scale down slow — so a brief dip
  in load doesn't cause the host to flap on and off.
- Cooldown also applies as a minimum gap between any two actions on the same
  host, regardless of direction.

## Test button

The **Test** button on this plugin's config page does not power anything on
or off. It evaluates one rule's current metrics and reports what action
would be taken, so you can sanity-check thresholds before relying on them.

## Requires

`xo-server-nanokvm` only if any rule uses the `nanokvm` power-on provider.
For the `native` provider, the target host needs a power-on mode already
configured in XO (**Host > Advanced**) — this plugin does not set that up.
