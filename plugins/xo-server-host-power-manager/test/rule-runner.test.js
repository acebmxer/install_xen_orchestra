'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const {
  cpuTriggerActive,
  cpuTriggerIncomplete,
  memoryTriggerActive,
  memoryTriggerIncomplete,
  decide,
  computeCpuValue,
  computeMemoryValue,
  RuleState,
  tick,
  blockedReason,
} = require('../lib/rule-runner')

const GB = 1024 * 1024 * 1024
const COOLDOWN_MINUTES = 10
const COOLDOWN_MS = COOLDOWN_MINUTES * 60 * 1000

function baseRule(overrides = {}) {
  return {
    cpu: { metric: 'none' },
    memory: { metric: 'none' },
    cooldownMinutes: COOLDOWN_MINUTES,
    ...overrides,
  }
}

test('cpuTriggerActive/cpuTriggerIncomplete distinguish unset, half-configured, and fully-configured', () => {
  assert.equal(cpuTriggerActive(baseRule()), false)
  assert.equal(cpuTriggerIncomplete(baseRule()), false)

  const halfConfigured = baseRule({ cpu: { metric: 'percent', powerOnAbove: 80 } })
  assert.equal(cpuTriggerActive(halfConfigured), false)
  assert.equal(cpuTriggerIncomplete(halfConfigured), true)

  const configured = baseRule({ cpu: { metric: 'percent', powerOnAbove: 80, powerOffBelow: 20 } })
  assert.equal(cpuTriggerActive(configured), true)
  assert.equal(cpuTriggerIncomplete(configured), false)
})

test('memoryTriggerActive/memoryTriggerIncomplete mirror the CPU trigger rules', () => {
  const configured = baseRule({ memory: { metric: 'percentFree', powerOnBelow: 15, powerOffAbove: 40 } })
  assert.equal(memoryTriggerActive(configured), true)
  assert.equal(memoryTriggerIncomplete(configured), false)

  const halfConfigured = baseRule({ memory: { metric: 'percentFree', powerOnBelow: 15 } })
  assert.equal(memoryTriggerActive(halfConfigured), false)
  assert.equal(memoryTriggerIncomplete(halfConfigured), true)
})

test('computeMemoryValue returns null when the memory trigger is not active', () => {
  assert.equal(computeMemoryValue(baseRule(), []), null)
})

test('computeMemoryValue supports all four memory metrics', () => {
  const hosts = [
    { memory: { size: 64 * GB, usage: 49 * GB } }, // 15GB free
    { memory: { size: 64 * GB, usage: 24 * GB } }, // 40GB free
  ]
  const ruleWith = metric => baseRule({ memory: { metric, powerOnBelow: 1, powerOffAbove: 2 } })

  assert.equal(computeMemoryValue(ruleWith('percentFree'), hosts), (55 / 128) * 100)
  assert.equal(computeMemoryValue(ruleWith('absoluteFreeGb'), hosts), 55)
  assert.equal(computeMemoryValue(ruleWith('percentFreeMin'), hosts), (15 / 64) * 100)
  assert.equal(computeMemoryValue(ruleWith('absoluteFreeMinGb'), hosts), 15)
})

test('computeCpuValue returns null when the CPU trigger is not active, otherwise dispatches on metric', async () => {
  assert.equal(await computeCpuValue({}, baseRule(), []), null)

  const percentXo = { getXapiHostStats: async () => ({ stats: { cpus: { 0: [60] } } }) }
  const percentRule = baseRule({ cpu: { metric: 'percent', powerOnAbove: 80, powerOffBelow: 20 } })
  assert.equal(await computeCpuValue(percentXo, percentRule, [{ id: 'h1' }]), 60)

  const ratioRule = baseRule({ cpu: { metric: 'vcpuRatio', powerOnAbove: 2, powerOffBelow: 1 } })
  const ratioXo = { getObjects: () => ({}) }
  assert.equal(await computeCpuValue(ratioXo, ratioRule, [{ id: 'h1', cpus: { cores: 4 } }]), 0)
})

test('decide: power-on fires immediately when either resource is tight and the host is off', () => {
  const rule = baseRule({
    cpu: { metric: 'percent', powerOnAbove: 80, powerOffBelow: 20 },
    memory: { metric: 'percentFree', powerOnBelow: 15, powerOffAbove: 40 },
  })

  assert.deepEqual(decide({ rule, cpuValue: 90, memoryValue: 60, hostIsRunning: false, offEligibleSinceMs: null, now: 1000 }), {
    action: 'power-on',
    offEligibleSinceMs: null,
  })
  assert.deepEqual(decide({ rule, cpuValue: 10, memoryValue: 5, hostIsRunning: false, offEligibleSinceMs: null, now: 1000 }), {
    action: 'power-on',
    offEligibleSinceMs: null,
  })
  assert.deepEqual(decide({ rule, cpuValue: 10, memoryValue: 60, hostIsRunning: false, offEligibleSinceMs: null, now: 1000 }), {
    action: 'none',
    offEligibleSinceMs: null,
  })
})

test('decide: power-off requires both resources comfortable, continuously, for the full cooldown', () => {
  const rule = baseRule({
    cpu: { metric: 'percent', powerOnAbove: 80, powerOffBelow: 20 },
    memory: { metric: 'percentFree', powerOnBelow: 15, powerOffAbove: 40 },
  })

  // CPU still hot -> stays on, eligibility clock not running.
  assert.deepEqual(decide({ rule, cpuValue: 50, memoryValue: 60, hostIsRunning: true, offEligibleSinceMs: null, now: 0 }), {
    action: 'none',
    offEligibleSinceMs: null,
  })

  // Both comfortable, clock just started -> not yet eligible.
  assert.deepEqual(decide({ rule, cpuValue: 10, memoryValue: 60, hostIsRunning: true, offEligibleSinceMs: null, now: 0 }), {
    action: 'none',
    offEligibleSinceMs: 0,
  })

  // Still comfortable, cooldown not yet elapsed.
  assert.deepEqual(
    decide({ rule, cpuValue: 10, memoryValue: 60, hostIsRunning: true, offEligibleSinceMs: 0, now: COOLDOWN_MS - 1 }),
    { action: 'none', offEligibleSinceMs: 0 }
  )

  // Cooldown elapsed -> power off.
  assert.deepEqual(decide({ rule, cpuValue: 10, memoryValue: 60, hostIsRunning: true, offEligibleSinceMs: 0, now: COOLDOWN_MS }), {
    action: 'power-off',
    offEligibleSinceMs: 0,
  })

  // A dip back to uncomfortable resets the eligibility clock.
  assert.deepEqual(decide({ rule, cpuValue: 90, memoryValue: 60, hostIsRunning: true, offEligibleSinceMs: 0, now: COOLDOWN_MS }), {
    action: 'none',
    offEligibleSinceMs: null,
  })
})

test('decide: a trigger left "Not used" never requests power-on and never blocks power-off', () => {
  const memoryOnlyRule = baseRule({ memory: { metric: 'percentFree', powerOnBelow: 15, powerOffAbove: 40 } })

  // Memory alone is tight enough to power on, even with an absurd (but inactive) CPU value.
  const on = decide({ rule: memoryOnlyRule, cpuValue: 999, memoryValue: 5, hostIsRunning: false, offEligibleSinceMs: null, now: 0 })
  assert.equal(on.action, 'power-on')

  // CPU is never active, so it can't block power-off once memory is comfortable and cooldown has elapsed.
  const off = decide({
    rule: memoryOnlyRule,
    cpuValue: 999,
    memoryValue: 60,
    hostIsRunning: true,
    offEligibleSinceMs: 0,
    now: COOLDOWN_MS,
  })
  assert.equal(off.action, 'power-off')
})

// A pool with one running host (h1, tight on memory) and the managed host
// (h3, off). getXapiHostStats takes `statsDelayMs` to answer, standing in
// for a stats call slower than the poll interval.
function tickFixture({ statsDelayMs = 0, h3 = {}, led = 'off' } = {}) {
  const objects = {
    h1: {
      type: 'host',
      id: 'h1',
      $poolId: 'pool1',
      enabled: true,
      power_state: 'Running',
      memory: { size: 64 * GB, usage: 60 * GB },
    },
    h3: { type: 'host', id: 'h3', name_label: 'host3', $poolId: 'pool1', enabled: false, power_state: 'Halted', ...h3 },
  }
  const presses = []
  const xo = {
    getObject: id => objects[id],
    getObjects: () => objects,
    getXapiHostStats: hostId =>
      new Promise(resolve => setTimeout(() => resolve({ stats: { cpus: { 0: [hostId === 'h1' ? 10 : 0] } } }), statsDelayMs)),
  }
  const nanokvm = {
    supportsHost: () => true,
    getPowerState: async () => led,
    powerOn: async hostId => {
      presses.push(hostId)
    },
  }
  const rule = baseRule({
    targetHostId: 'h3',
    powerProvider: 'nanokvm',
    cpu: { metric: 'percent', powerOnAbove: 80, powerOffBelow: 20 },
    memory: { metric: 'percentFree', powerOnBelow: 15, powerOffAbove: 40 },
  })
  return { xo, rule, presses, powerProviders: new Map([['nanokvm', nanokvm]]) }
}

test('tick: a second tick while the first is still reading stats does not press the button again', async () => {
  const { xo, rule, presses, powerProviders } = tickFixture({ statsDelayMs: 50 })
  const state = new RuleState()

  const first = tick({ xo, rule, state, powerProviders })
  const second = tick({ xo, rule, state, powerProviders })
  await Promise.all([first, second])

  assert.deepEqual(presses, ['h3'])
  assert.equal(state.busy, false)
})

test('tick: a failed power-off waits for the cooldown before trying again', async () => {
  const host3 = { type: 'host', id: 'h3', name_label: 'host3', $poolId: 'pool1', enabled: true, power_state: 'Running' }
  const objects = {
    h1: { type: 'host', id: 'h1', $poolId: 'pool1', enabled: true, power_state: 'Running', memory: { size: 64 * GB, usage: 8 * GB } },
    h3: { ...host3, memory: { size: 64 * GB, usage: 8 * GB } },
  }
  let shutdowns = 0
  const xo = {
    getObject: id => objects[id],
    getObjects: () => objects,
    getXapi: () => ({
      shutdownHost: async () => {
        shutdowns++
        throw new Error('VM_REQUIRES_SR')
      },
    }),
  }
  const rule = baseRule({
    targetHostId: 'h3',
    powerProvider: 'native',
    memory: { metric: 'percentFree', powerOnBelow: 15, powerOffAbove: 40 },
  })
  const state = new RuleState()
  state.offEligibleSinceMs = Date.now() - COOLDOWN_MS - 1

  await tick({ xo, rule, state, powerProviders: new Map() })
  await tick({ xo, rule, state, powerProviders: new Map() })
  await tick({ xo, rule, state, powerProviders: new Map() })

  assert.equal(shutdowns, 1)
  assert.ok(state.lastActionAt > 0, 'the failed attempt starts the cooldown')
})

test('tick: no NanoKVM press while the power LED says on or cannot be read', async () => {
  for (const led of ['on', 'unknown']) {
    const { xo, rule, presses, powerProviders } = tickFixture({ led })
    const state = new RuleState()

    await tick({ xo, rule, state, powerProviders })

    assert.deepEqual(presses, [], `LED "${led}" must not be pressed`)
    assert.equal(state.lastActionAt, 0, 'a skipped press is not counted as an action')
  }

  // Positive control: same pool, LED off -> pressed.
  const { xo, rule, presses, powerProviders } = tickFixture({ led: 'off' })
  await tick({ xo, rule, state: new RuleState(), powerProviders })
  assert.deepEqual(presses, ['h3'])
})

test('tick: a host XO shows as Unknown is neither powered on nor shut down', async () => {
  const { xo, rule, presses, powerProviders } = tickFixture({ h3: { power_state: 'Unknown' } })
  await tick({ xo, rule, state: new RuleState(), powerProviders })
  assert.deepEqual(presses, [])
})

test('tick: a disabled (maintenance) running host is not shut down', async () => {
  const objects = {
    h1: { type: 'host', id: 'h1', $poolId: 'pool1', enabled: true, power_state: 'Running', memory: { size: 64 * GB, usage: 8 * GB } },
    h3: { type: 'host', id: 'h3', name_label: 'host3', $poolId: 'pool1', enabled: false, power_state: 'Running' },
  }
  let shutdowns = 0
  const xo = {
    getObject: id => objects[id],
    getObjects: () => objects,
    getXapi: () => ({
      shutdownHost: async () => {
        shutdowns++
      },
    }),
  }
  const rule = baseRule({
    targetHostId: 'h3',
    powerProvider: 'native',
    memory: { metric: 'percentFree', powerOnBelow: 15, powerOffAbove: 40 },
  })
  const state = new RuleState()
  state.offEligibleSinceMs = Date.now() - COOLDOWN_MS - 1

  await tick({ xo, rule, state, powerProviders: new Map() })
  assert.equal(shutdowns, 0)

  // Positive control: the same host, enabled again, is shut down.
  objects.h3.enabled = true
  await tick({ xo, rule, state, powerProviders: new Map() })
  assert.equal(shutdowns, 1)
})

test('tick: after a power-on, no second press until the boot wait has passed', async () => {
  const { xo, rule, presses, powerProviders } = tickFixture()
  rule.bootWaitMinutes = 30 // longer than the fixture's 10-minute cooldown
  const state = new RuleState()

  await tick({ xo, rule, state, powerProviders })
  assert.deepEqual(presses, ['h3'])

  // Cooldown over, host still shown Halted, LED not reporting on (e.g. the
  // LED header isn't wired): the boot wait still holds the second press.
  state.lastActionAt -= COOLDOWN_MS + 1
  state.poweredOnAt -= COOLDOWN_MS + 1
  await tick({ xo, rule, state, powerProviders })
  assert.deepEqual(presses, ['h3'])

  // Boot wait over -> the host never came up, so it is pressed again.
  state.poweredOnAt -= 30 * 60 * 1000
  await tick({ xo, rule, state, powerProviders })
  assert.deepEqual(presses, ['h3', 'h3'])
})

test('blockedReason: the boot wait holds a power-on until it has passed, never a power-off', () => {
  const rule = baseRule({ bootWaitMinutes: 10 })
  const state = new RuleState()
  state.poweredOnAt = 1000
  const halted = { power_state: 'Halted', enabled: false }
  assert.match(blockedReason({ action: 'power-on', host: halted, rule, state, now: 2000 }), /boot wait/)
  assert.equal(blockedReason({ action: 'power-on', host: halted, rule, state, now: 1000 + 10 * 60 * 1000 }), null)
  assert.equal(blockedReason({ action: 'power-off', host: { power_state: 'Running', enabled: true }, rule, state, now: 2000 }), null)
})

test('tick: a host seen Running ends the boot wait', async () => {
  const { xo, rule, powerProviders } = tickFixture({ h3: { power_state: 'Running', enabled: true } })
  const state = new RuleState()
  state.poweredOnAt = Date.now()
  await tick({ xo, rule, state, powerProviders })
  assert.equal(state.poweredOnAt, null)
})
