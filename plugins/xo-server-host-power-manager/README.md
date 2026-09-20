# xo-server-host-power-manager

Xen Orchestra plugin that powers an "extra" pool host on when the rest of
the pool is under CPU or memory pressure, and powers it back off once it
isn't needed anymore.

- **Power-on** goes through either XO's own built-in host power-on
  (iLO/DRAC/Wake-on-LAN — whatever's already configured on the host under
  **Host > Advanced**) or [xo-server-nanokvm](../xo-server-nanokvm), for
  hosts that only have a NanoKVM device. Pick per rule.
- **Power-off** always goes through XO's own `Host.shutdown`, regardless of
  provider — never NanoKVM or IPMI. It disables the host and evacuates any
  running VMs first (live migration, the same path XO's own "enable
  maintenance mode" uses), then shuts it down cleanly.
- If the pool has **HA** enabled and powering off this host would leave it
  without enough spare capacity for its configured failover plan, XAPI
  refuses the power-off; the plugin logs that plainly instead of a generic
  error.

## Install

Copy this folder to `/usr/local/lib/node_modules/xo-server-host-power-manager`
on the XO server, then restart `xo-server`. If you're using
[install_xen_orchestra](https://github.com/acebmxer/install_xen_orchestra),
its Custom Plugins menu does this for you automatically.

## Configure

In XO: **Settings > Plugins > host-power-manager**. Add one **rule** per
extra host:

| Field | Meaning |
| --- | --- |
| Extra host | The XO UUID of the host to manage |
| Power-on provider | `native` (iLO/DRAC/WoL) or `nanokvm` |
| CPU trigger | Metric (`Not used`, average % **or** vCPU:pCPU ratio) + power-on/power-off thresholds |
| Memory trigger | Metric (`Not used`, free % **or** free GB) + power-on/power-off thresholds |
| Poll interval | How often to re-check, in seconds (default 60) |
| Cooldown | Minutes; see **Behavior** below |

Both triggers are optional and default to `Not used` on a new rule — pick a
Metric other than `Not used` and fill in its two thresholds to turn a trigger
on. Use CPU only, memory only, or both; at least one must be configured or
the rule will never power the host on.

Saving changes here takes effect immediately — no `xo-server` restart
needed. Each rule's polling restarts fresh on save, so a lowered Cooldown or
Poll interval applies right away rather than waiting for the next restart.

All metrics are computed from **every currently running host in the pool,
including the managed host itself** when it's running — matching what XO's
own pool dashboard shows. A host being considered for power-on is already
not running, so it's naturally excluded from its own trigger's calculation
without any special-casing.

This isn't a safety check — the actual guarantee that powering a host off
won't strand VMs is XAPI's own evacuation, which refuses (and leaves the
host running) if its VMs can't really be placed elsewhere. This plugin's
thresholds only decide *when to try*; XAPI decides whether it's safe, on
every attempt.

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
- If only one trigger is configured (see **Configure** above), that trigger
  alone decides both power-on and power-off — the unset one is ignored
  entirely.
- If a power-off is blocked by the pool's HA failover plan, the rule leaves
  the host running and retries on the next poll — it never forces the
  evacuation or bypasses HA.

## Test button

The **Test** button on this plugin's config page does not power anything on
or off. It evaluates one rule's current metrics and reports what action
would be taken, so you can sanity-check thresholds before relying on them.

XO's own "Test plugin" dialog only ever shows a static "appears to be
working" message — it discards the actual result. To see what a Test click
actually computed (current CPU/memory values, whether each trigger is
active, and `wouldDo`), check `sudo journalctl -u xo-server` right after
clicking it; the result is logged there.

## Requires

`xo-server-nanokvm` only if any rule uses the `nanokvm` power-on provider.
For the `native` provider, the target host needs a power-on mode already
configured in XO (**Host > Advanced**) — this plugin does not set that up.
