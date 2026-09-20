'use strict'

const { getAlwaysOnHosts, getAverageCpuPercent, getVcpuRatio, getMemory } = require('./metrics')
const log = require('./log')

const BYTES_PER_GB = 1024 * 1024 * 1024

// Decides what (if anything) to do about one rule's target host, given the
// current metrics. Kept pure/synchronous so it's easy to reason about (and
// test) independently of XAPI calls and timers.
//
// Power-on reacts immediately: either resource being tight is enough reason
// to bring the extra host up. Power-off requires *both* resources to be
// comfortable, and only after they've stayed that way continuously for
// `cooldownMinutes` (via `offEligibleSinceMs`) — scale up fast, scale down
// slow, so a brief dip doesn't cause flapping.
function decide({ rule, cpuValue, memoryValue, hostIsRunning, offEligibleSinceMs, now }) {
  const cpuWantsMore = cpuValue >= rule.cpu.powerOnAbove
  const memoryWantsMore = memoryValue <= rule.memory.powerOnBelow

  if (!hostIsRunning) {
    if (cpuWantsMore || memoryWantsMore) {
      return { action: 'power-on', offEligibleSinceMs: null }
    }
    return { action: 'none', offEligibleSinceMs: null }
  }

  const cpuComfortable = cpuValue <= rule.cpu.powerOffBelow
  const memoryComfortable = memoryValue >= rule.memory.powerOffAbove
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
  return rule.cpu.metric === 'vcpuRatio' ? getVcpuRatio(xo, hosts) : getAverageCpuPercent(xo, hosts)
}

function computeMemoryValue(rule, hosts) {
  const { totalBytes, freeBytes } = getMemory(hosts)
  if (rule.memory.metric === 'absoluteFreeGb') {
    return freeBytes / BYTES_PER_GB
  }
  return totalBytes === 0 ? 100 : (freeBytes / totalBytes) * 100
}

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

async function powerOff({ xo, rule, host }) {
  log.info(`shutting down host ${host.name_label} (${host.id}) (evacuating any running VMs first)`)
  await xo.getXapi(host.id).shutdownHost(host.id)
}
