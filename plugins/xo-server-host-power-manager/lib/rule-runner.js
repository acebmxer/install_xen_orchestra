'use strict'

const { getAlwaysOnHosts, getAverageCpuPercent, getVcpuRatio, getMemory } = require('./metrics')
const log = require('./log')

const BYTES_PER_GB = 1024 * 1024 * 1024

// A trigger (CPU or memory) is only in play for a rule once its Metric is
// set to something other than "not used" AND both its thresholds are set —
// setting Metric to "Not used" (the default for a new rule) is how a rule
// opts out of using that resource, so it can use CPU only, memory only, or
// both. The threshold check also covers a metric picked with thresholds
// not yet filled in, which configure()'s warning flags separately.
function cpuTriggerActive(rule) {
  return rule.cpu.metric !== 'none' && rule.cpu.powerOnAbove !== undefined && rule.cpu.powerOffBelow !== undefined
}
exports.cpuTriggerActive = cpuTriggerActive

function memoryTriggerActive(rule) {
  return (
    rule.memory.metric !== 'none' && rule.memory.powerOnBelow !== undefined && rule.memory.powerOffAbove !== undefined
  )
}
exports.memoryTriggerActive = memoryTriggerActive

// A trigger whose Metric is set but is missing one or both thresholds —
// distinct from "not used", this is a rule left half-configured.
function cpuTriggerIncomplete(rule) {
  return rule.cpu.metric !== 'none' && !cpuTriggerActive(rule)
}
exports.cpuTriggerIncomplete = cpuTriggerIncomplete

function memoryTriggerIncomplete(rule) {
  return rule.memory.metric !== 'none' && !memoryTriggerActive(rule)
}
exports.memoryTriggerIncomplete = memoryTriggerIncomplete

// Decides what (if anything) to do about one rule's target host, given the
// current metrics. Kept pure/synchronous so it's easy to reason about (and
// test) independently of XAPI calls and timers.
//
// Power-on reacts immediately: either resource being tight is enough reason
// to bring the extra host up. Power-off requires *both* resources to be
// comfortable, and only after they've stayed that way continuously for
// `cooldownMinutes` (via `offEligibleSinceMs`) — scale up fast, scale down
// slow, so a brief dip doesn't cause flapping. A trigger that isn't active
// never asks for power-on and is always "comfortable", so a rule using only
// one resource behaves as if the other were never tight.
function decide({ rule, cpuValue, memoryValue, hostIsRunning, offEligibleSinceMs, now }) {
  const cpuActive = cpuTriggerActive(rule)
  const memoryActive = memoryTriggerActive(rule)

  const cpuWantsMore = cpuActive && cpuValue >= rule.cpu.powerOnAbove
  const memoryWantsMore = memoryActive && memoryValue <= rule.memory.powerOnBelow

  if (!hostIsRunning) {
    if (cpuWantsMore || memoryWantsMore) {
      return { action: 'power-on', offEligibleSinceMs: null }
    }
    return { action: 'none', offEligibleSinceMs: null }
  }

  const cpuComfortable = !cpuActive || cpuValue <= rule.cpu.powerOffBelow
  const memoryComfortable = !memoryActive || memoryValue >= rule.memory.powerOffAbove
  const comfortable = cpuComfortable && memoryComfortable

  if (!comfortable) {
    return { action: 'none', offEligibleSinceMs: null }
  }

  const eligibleSince = offEligibleSinceMs ?? now
  const cooldownMs = rule.cooldownMinutes * 60 * 1000
  if (now - eligibleSince >= cooldownMs) {
    return { action: 'power-off', offEligibleSinceMs: eligibleSince }
  }
  return { action: 'none', offEligibleSinceMs: eligibleSince }
}
exports.decide = decide

async function computeCpuValue(xo, rule, hosts) {
  if (!cpuTriggerActive(rule)) {
    return null
  }
  return rule.cpu.metric === 'vcpuRatio' ? getVcpuRatio(xo, hosts) : getAverageCpuPercent(xo, hosts)
}
exports.computeCpuValue = computeCpuValue

function computeMemoryValue(rule, hosts) {
  if (!memoryTriggerActive(rule)) {
    return null
  }
  const { totalBytes, freeBytes } = getMemory(hosts)
  if (rule.memory.metric === 'absoluteFreeGb') {
    return freeBytes / BYTES_PER_GB
  }
  return totalBytes === 0 ? 100 : (freeBytes / totalBytes) * 100
}
exports.computeMemoryValue = computeMemoryValue

// One rule's live state between ticks: is a power action already in flight,
// when did it last run, and (for power-off) since when have both resources
// been comfortable.
class RuleState {
  constructor() {
    this.lastActionAt = 0
    this.offEligibleSinceMs = null
    this.busy = false
  }
}
exports.RuleState = RuleState

async function tick({ xo, rule, state, powerProviders }) {
  if (state.busy) {
    return
  }

  let host
  try {
    host = xo.getObject(rule.targetHostId)
  } catch (error) {
    log.warn(`rule "${rule.label || rule.targetHostId}": target host not found`, { error })
    return
  }

  const now = Date.now()
  const cooldownMs = rule.cooldownMinutes * 60 * 1000
  if (now - state.lastActionAt < cooldownMs) {
    return
  }

  const hosts = getAlwaysOnHosts(xo, host.$poolId, host.id)
  const [cpuValue, memoryValue] = await Promise.all([
    computeCpuValue(xo, rule, hosts),
    Promise.resolve(computeMemoryValue(rule, hosts)),
  ])

  const hostIsRunning = host.power_state === 'Running'
  const result = decide({
    rule,
    cpuValue,
    memoryValue,
    hostIsRunning,
    offEligibleSinceMs: state.offEligibleSinceMs,
    now,
  })
  state.offEligibleSinceMs = result.offEligibleSinceMs

  if (result.action === 'none') {
    return
  }

  state.busy = true
  try {
    if (result.action === 'power-on') {
      await powerOn({ xo, rule, host, powerProviders })
    } else {
      await powerOff({ xo, rule, host })
    }
    state.lastActionAt = now
  } catch (error) {
    log.error(`rule "${rule.label || rule.targetHostId}": ${result.action} failed`, { error })
  } finally {
    state.busy = false
  }
}
exports.tick = tick

async function powerOn({ xo, rule, host, powerProviders }) {
  if (rule.powerProvider === 'nanokvm') {
    const provider = powerProviders.get('nanokvm')
    if (provider === undefined) {
      throw new Error('powerProvider is "nanokvm" but xo-server-nanokvm is not installed/loaded')
    }
    if (!provider.supportsHost(host.id)) {
      throw new Error(`xo-server-nanokvm has no device configured for host ${host.id}`)
    }
    log.info(`powering on host ${host.name_label} (${host.id}) via NanoKVM`)
    await provider.powerOn(host.id)
    return
  }

  if (!host.powerOnMode) {
    throw new Error(
      `powerProvider is "native" but host ${host.name_label} (${host.id}) has no power-on mode configured (Host > Advanced in XO)`
    )
  }
  log.info(`powering on host ${host.name_label} (${host.id}) via ${host.powerOnMode}`)
  await xo.getXapi(host.id).powerOnHost(host.id)
}

// shutdownHost() (default options: no force, no bypassEvacuate) already
// disables the host and evacuates its VMs via live migration before
// shutting it down — the exact same xapi.clearHost() path XO's own
// "enable maintenance mode" goes through. It never uses NanoKVM/IPMI;
// power-off always goes through this one XO/XAPI call.
//
// If the pool has HA enabled, XAPI itself refuses an evacuate/disable that
// would leave the pool without enough spare capacity to honor its
// configured "host failures to tolerate" (HA_OPERATION_WOULD_BREAK_FAILOVER_PLAN).
// That check depends on live pool capacity and the HA failover plan XAPI
// already computes, so it's left to XAPI rather than re-implemented here —
// this just turns that rejection into a clear log message instead of a
// generic failure.
async function powerOff({ xo, rule, host }) {
  log.info(`shutting down host ${host.name_label} (${host.id}) (evacuating any running VMs first)`)
  try {
    await xo.getXapi(host.id).shutdownHost(host.id)
  } catch (error) {
    if (error?.code === 'HA_OPERATION_WOULD_BREAK_FAILOVER_PLAN') {
      throw new Error(
        `cannot power off host ${host.name_label} (${host.id}): the pool's HA failover plan needs it to stay up (Pool > Advanced > HA, "host failures to tolerate") — leave it running or lower that setting`
      )
    }
    throw error
  }
}
