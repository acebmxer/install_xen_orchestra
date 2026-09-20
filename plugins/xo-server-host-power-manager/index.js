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

const { RuleState, tick, decide } = require('./lib/rule-runner')
const { getAlwaysOnHosts, getAverageCpuPercent, getMemory, getVcpuRatio } = require('./lib/metrics')
const log = require('./lib/log')

const cpuMetricSchema = {
  type: 'object',
  title: 'CPU trigger',
  properties: {
    metric: {
      type: 'string',
      title: 'Metric',
      enum: ['percent', 'vcpuRatio'],
      enumNames: ['Average CPU utilization %', 'vCPU:pCPU ratio'],
      default: 'percent',
    },
    powerOnAbove: {
      type: 'number',
      title: 'Power on when at/above',
      description: 'e.g. 80 for 80% utilization, or 4 for a 4:1 vCPU:pCPU ratio.',
    },
    powerOffBelow: {
      type: 'number',
      title: 'Power off when at/below',
      description: 'Must be lower than "power on" — the gap between them prevents flapping.',
    },
  },
  required: ['metric', 'powerOnAbove', 'powerOffBelow'],
}

const memoryMetricSchema = {
  type: 'object',
  title: 'Memory trigger',
  properties: {
    metric: {
      type: 'string',
      title: 'Metric',
      enum: ['percentFree', 'absoluteFreeGb'],
      enumNames: ['Free memory %', 'Free memory (GB)'],
      default: 'percentFree',
    },
    powerOnBelow: {
      type: 'number',
      title: 'Power on when at/below',
      description: 'e.g. 15 for 15% free, or 32 for 32 GB free.',
    },
    powerOffAbove: {
      type: 'number',
      title: 'Power off when at/above',
      description: 'Must be higher than "power on" — the gap between them prevents flapping.',
    },
  },
  required: ['metric', 'powerOnBelow', 'powerOffAbove'],
}

exports.configurationSchema = {
  type: 'object',
  properties: {
    rules: {
      type: 'array',
      title: 'Rules',
      description: 'One rule per extra host to manage.',
      items: {
        type: 'object',
        title: 'Rule',
        properties: {
          label: {
            type: 'string',
            title: 'Label',
            description: 'Free-text name for logs, e.g. "host3".',
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
    configure(configuration) {
      clearTimers()
      rules = (configuration && configuration.rules) || []
      // Rules that no longer exist keep no state around.
      const currentIds = new Set(rules.map(rule => rule.targetHostId))
      for (const id of ruleStates.keys()) {
        if (!currentIds.has(id)) {
          ruleStates.delete(id)
        }
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
      const hosts = getAlwaysOnHosts(xo, host.$poolId, host.id)
      const cpuValue = rule.cpu.metric === 'vcpuRatio' ? getVcpuRatio(xo, hosts) : await getAverageCpuPercent(xo, hosts)
      const { totalBytes, freeBytes } = getMemory(hosts)
      const memoryValue =
        rule.memory.metric === 'absoluteFreeGb'
          ? freeBytes / (1024 * 1024 * 1024)
          : totalBytes === 0
            ? 100
            : (freeBytes / totalBytes) * 100

      const state = ruleStates.get(targetHostId) || new RuleState()
      const result = decide({
        rule,
        cpuValue,
        memoryValue,
        hostIsRunning: host.power_state === 'Running',
        offEligibleSinceMs: state.offEligibleSinceMs,
        now: Date.now(),
      })

      return {
        hostPowerState: host.power_state,
        alwaysOnHostCount: hosts.length,
        cpuMetric: rule.cpu.metric,
        cpuValue,
        memoryMetric: rule.memory.metric,
        memoryValue,
        wouldDo: result.action,
      }
    },
  }
}
