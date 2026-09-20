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
