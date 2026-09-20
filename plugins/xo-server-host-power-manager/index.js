'use strict'

// xo-server-host-power-manager
//
// Powers an "extra" host on when the rest of the pool is under CPU or
// memory pressure, and powers it back off (evacuating VMs first, via XO's
// own Host.shutdown) once it's no longer needed. Power-on can go through
// either XO's built-in host power-on (iLO/DRAC/Wake-on-LAN, already
// configured on the host in Host > Advanced) or xo-server-nanokvm, for
// hosts that only have a NanoKVM device.
//
// This plugin only holds policy (thresholds, which host, which provider).
// It never talks to a BMC or a NanoKVM device directly.

const {
  RuleState,
  tick,
  decide,
  computeCpuValue,
  computeMemoryValue,
  cpuTriggerActive,
  memoryTriggerActive,
  cpuTriggerIncomplete,
  memoryTriggerIncomplete,
} = require('./lib/rule-runner')
const { getRunningHosts } = require('./lib/metrics')
const log = require('./lib/log')

const cpuMetricSchema = {
  type: 'object',
  title: 'CPU trigger',
  description: 'Set Metric to "Not used" to skip CPU for this rule.',
  properties: {
    metric: {
      type: 'string',
      title: 'Metric',
      enum: ['none', 'percent', 'vcpuRatio'],
      enumNames: ['Not used', 'Average CPU utilization %', 'vCPU:pCPU ratio'],
      default: 'none',
    },
    powerOnAbove: {
      type: 'number',
      title: 'Power on when at/above',
      description: 'e.g. 80 for 80% utilization, or 4 for a 4:1 vCPU:pCPU ratio. Ignored when Metric is "Not used".',
    },
    powerOffBelow: {
      type: 'number',
      title: 'Power off when at/below',
      description: 'Must be lower than "power on" — the gap between them prevents flapping. Ignored when Metric is "Not used".',
    },
  },
  required: ['metric'],
}

const memoryMetricSchema = {
  type: 'object',
  title: 'Memory trigger',
  description: 'Set Metric to "Not used" to skip memory for this rule.',
  properties: {
    metric: {
      type: 'string',
      title: 'Metric',
      enum: ['none', 'percentFree', 'absoluteFreeGb'],
      enumNames: ['Not used', 'Free memory %', 'Free memory (GB)'],
      default: 'none',
    },
    powerOnBelow: {
      type: 'number',
      title: 'Power on when at/below',
      description: 'e.g. 15 for 15% free, or 32 for 32 GB free. Ignored when Metric is "Not used".',
    },
    powerOffAbove: {
      type: 'number',
      title: 'Power off when at/above',
      description: 'Must be higher than "power on" — the gap between them prevents flapping. Ignored when Metric is "Not used".',
    },
  },
  required: ['metric'],
}

exports.configurationSchema = {
  type: 'object',
  properties: {
    rules: {
      type: 'array',
      title: 'Rules',
      description:
        'One rule per extra host to manage. Set a trigger\'s Metric to "Not used" to skip it. Power-on: either CPU or memory being tight is enough. Power-off: every configured trigger must be comfortable at once (just the one, if only CPU or only memory is set).',
      items: {
        type: 'object',
        title: 'Rule',
        properties: {
          label: {
            type: 'string',
            title: 'Label',
            description: 'Free-text name for logs, e.g. "Power on/off extra host".',
          },
          enabled: {
            type: 'boolean',
            title: 'Enabled',
            default: true,
          },
          targetHostId: {
            type: 'string',
            title: 'Extra host (XO host UUID)',
          },
          powerProvider: {
            type: 'string',
            title: 'Power-on provider',
            enum: ['native', 'nanokvm'],
            enumNames: ['XO built-in (iLO/DRAC/Wake-on-LAN, set on the host in XO)', 'NanoKVM (xo-server-nanokvm)'],
            default: 'native',
          },
          cpu: cpuMetricSchema,
          memory: memoryMetricSchema,
          pollIntervalSeconds: {
            type: 'number',
            title: 'Poll interval (seconds)',
            default: 60,
          },
          cooldownMinutes: {
            type: 'number',
            title: 'Cooldown (minutes)',
            default: 15,
            description:
              'Minimum time between two power actions on this host, and how long CPU and memory must both stay comfortable before powering it off. Power-on is not delayed by this — only throttled by it.',
          },
        },
        required: ['targetHostId', 'powerProvider', 'cpu', 'memory'],
      },
    },
  },
  required: ['rules'],
}

exports.testSchema = {
  type: 'object',
  properties: {
    targetHostId: {
      type: 'string',
      title: 'Extra host (XO host UUID)',
      description: 'Which configured rule to evaluate (matched by targetHostId). This does not power anything on or off — it only reports the current metrics and what would happen.',
    },
  },
  required: ['targetHostId'],
}

exports.default = function ({ xo }) {
  let rules = []
  const ruleStates = new Map()
  const timers = new Map()

  function clearTimers() {
    for (const timer of timers.values()) {
      clearInterval(timer)
    }
    timers.clear()
  }

  function startTimers() {
    for (const rule of rules) {
      if (rule.enabled === false) {
        continue
      }
      if (!ruleStates.has(rule.targetHostId)) {
        ruleStates.set(rule.targetHostId, new RuleState())
      }
      const state = ruleStates.get(rule.targetHostId)
      const intervalMs = (rule.pollIntervalSeconds || 60) * 1000
      const timer = setInterval(() => {
        tick({ xo, rule, state, powerProviders: xo.customHostPowerProviders || new Map() }).catch(error =>
          log.error(`unhandled error evaluating rule "${rule.label || rule.targetHostId}"`, { error })
        )
      }, intervalMs)
      timer.unref()
      timers.set(rule.targetHostId, timer)
    }
  }

  return {
    // xo-server calls configure() again, with { loaded: true }, every time
    // settings are saved on an already-running plugin -- it does NOT call
    // load() a second time (load() only ever fires once, at initial
    // activation). So a live settings change has to restart the timers
    // itself here, or the plugin goes inert (rules cleared, never
    // rescheduled) until xo-server is restarted.
    configure(configuration, { loaded } = {}) {
      clearTimers()
      rules = (configuration && configuration.rules) || []
      // Rules that no longer exist keep no state around.
      const currentIds = new Set(rules.map(rule => rule.targetHostId))
      for (const id of ruleStates.keys()) {
        if (!currentIds.has(id)) {
          ruleStates.delete(id)
        }
      }
      for (const rule of rules) {
        const label = rule.label || rule.targetHostId
        if (!cpuTriggerActive(rule) && !memoryTriggerActive(rule)) {
          log.warn(`rule "${label}" has neither a CPU nor a memory trigger configured — it will never power the host on`)
        }
        if (cpuTriggerIncomplete(rule)) {
          log.warn(`rule "${label}" has a CPU metric selected but is missing a power-on/power-off threshold — CPU trigger is ignored until both are set`)
        }
        if (memoryTriggerIncomplete(rule)) {
          log.warn(`rule "${label}" has a memory metric selected but is missing a power-on/power-off threshold — memory trigger is ignored until both are set`)
        }
      }
      if (loaded) {
        startTimers()
      }
    },

    load() {
      startTimers()
    },

    unload() {
      clearTimers()
    },

    // Read-only: reports the current metrics and what action would be
    // taken, without powering anything on or off.
    async test({ targetHostId }) {
      const rule = rules.find(candidate => candidate.targetHostId === targetHostId)
      if (rule === undefined) {
        throw new Error(`no rule configured for host ${targetHostId}`)
      }

      const host = xo.getObject(targetHostId)
      const hosts = getRunningHosts(xo, host.$poolId)
      const cpuValue = await computeCpuValue(xo, rule, hosts)
      const memoryValue = computeMemoryValue(rule, hosts)

      const state = ruleStates.get(targetHostId) || new RuleState()
      const result = decide({
        rule,
        cpuValue,
        memoryValue,
        hostIsRunning: host.power_state === 'Running',
        offEligibleSinceMs: state.offEligibleSinceMs,
        now: Date.now(),
      })

      const testResult = {
        hostPowerState: host.power_state,
        runningHostCount: hosts.length,
        cpuTriggerActive: cpuTriggerActive(rule),
        cpuTriggerIncomplete: cpuTriggerIncomplete(rule),
        cpuMetric: rule.cpu.metric,
        cpuValue,
        memoryTriggerActive: memoryTriggerActive(rule),
        memoryTriggerIncomplete: memoryTriggerIncomplete(rule),
        memoryMetric: rule.memory.metric,
        memoryValue,
        wouldDo: result.action,
      }
      // XO's own "Test plugin" button discards whatever this method
      // returns and shows a static "appears to be working" message on
      // success -- it never displays the payload. Logging it is the only
      // way these numbers are actually visible to whoever clicked Test.
      log.info(`rule "${rule.label || rule.targetHostId}" test result`, testResult)
      return testResult
    },
  }
}
