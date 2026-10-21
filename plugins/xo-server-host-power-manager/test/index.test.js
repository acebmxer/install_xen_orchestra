'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const plugin = require('../index')

function rule(overrides = {}) {
  return {
    label: 'extra host',
    targetHostId: 'h3',
    powerProvider: 'nanokvm',
    memory: { metric: 'percentFree', powerOnBelow: 55, powerOffAbove: 67 },
    pollIntervalSeconds: 30,
    cooldownMinutes: 1,
    ...overrides,
  }
}

// Records every interval the plugin creates and clears, without running any.
function withFakeIntervals(fn) {
  const realSet = global.setInterval
  const realClear = global.clearInterval
  const created = []
  const cleared = new Set()
  global.setInterval = () => {
    const timer = { unref() {} }
    created.push(timer)
    return timer
  }
  global.clearInterval = timer => cleared.add(timer)
  try {
    fn({ created, cleared })
  } finally {
    global.setInterval = realSet
    global.clearInterval = realClear
  }
}

test('configure refuses two rules for the same host', () => {
  const instance = plugin.default({ xo: {} })
  assert.throws(
    () => instance.configure({ rules: [rule(), rule({ label: 'second' })] }),
    /more than one rule manages host h3/
  )
})

test('a refused save keeps the running rules, and unload stops every timer', () => {
  withFakeIntervals(({ created, cleared }) => {
    const instance = plugin.default({ xo: {} })
    instance.configure({ rules: [rule(), rule({ targetHostId: 'h4' })] })
    instance.load()
    assert.equal(created.length, 2)

    assert.throws(() => instance.configure({ rules: [rule(), rule()] }, { loaded: true }))
    assert.equal(cleared.size, 0, 'the refused save must not stop the running rules')

    instance.unload()
    assert.equal(created.length, 2)
    assert.ok(
      created.every(timer => cleared.has(timer)),
      'every timer started must be stopped on unload'
    )
  })
})

test('configure refuses overlapping or equal CPU thresholds', () => {
  const instance = plugin.default({ xo: {} })
  for (const powerOffBelow of [80, 90]) {
    assert.throws(
      () =>
        instance.configure({
          rules: [rule({ memory: undefined, cpu: { metric: 'percent', powerOnAbove: 80, powerOffBelow } })],
        }),
      /rule "extra host", CPU trigger: "Power off when at\/below"/
    )
  }
  instance.configure({ rules: [rule({ cpu: { metric: 'percent', powerOnAbove: 80, powerOffBelow: 20 } })] })
})

test('configure refuses overlapping or equal memory thresholds', () => {
  const instance = plugin.default({ xo: {} })
  for (const powerOffAbove of [55, 40]) {
    assert.throws(
      () => instance.configure({ rules: [rule({ memory: { metric: 'percentFree', powerOnBelow: 55, powerOffAbove } })] }),
      /rule "extra host", memory trigger: "Power off when at\/above"/
    )
  }
})

test('thresholds of a trigger that is "Not used" are not checked', () => {
  const instance = plugin.default({ xo: {} })
  instance.configure({ rules: [rule({ cpu: { metric: 'none', powerOnAbove: 10, powerOffBelow: 90 } })] })
})

test('configure refuses a poll interval or cooldown below the minimum', () => {
  const instance = plugin.default({ xo: {} })
  for (const pollIntervalSeconds of [-1, 0, 9]) {
    assert.throws(() => instance.configure({ rules: [rule({ pollIntervalSeconds })] }), /Poll interval must be at least 10 seconds/)
  }
  for (const cooldownMinutes of [-5, 0]) {
    assert.throws(() => instance.configure({ rules: [rule({ cooldownMinutes })] }), /Cooldown must be at least 1 minute/)
  }
})

test('the settings form carries the same minimums, so XO rejects them on save', () => {
  const ruleSchema = plugin.configurationSchema.properties.rules.items.properties
  assert.equal(ruleSchema.pollIntervalSeconds.minimum, 10)
  assert.equal(ruleSchema.cooldownMinutes.minimum, 1)
  assert.equal(ruleSchema.bootWaitMinutes.minimum, 1)
  assert.equal(ruleSchema.bootWaitMinutes.default, 10)
})

test('configure refuses a boot wait under 1 minute, and a rule saved without one gets 10', () => {
  const instance = plugin.default({ xo: {} })
  for (const bootWaitMinutes of [0, -1]) {
    assert.throws(() => instance.configure({ rules: [rule({ bootWaitMinutes })] }), /Boot wait must be at least 1 minute/)
  }
  instance.configure({ rules: [rule()] })
})

test('the Test button reports an action held back, and why', async () => {
  const objects = {
    h1: { type: 'host', id: 'h1', $poolId: 'pool1', enabled: true, power_state: 'Running', memory: { size: 64, usage: 60 } },
    h3: { type: 'host', id: 'h3', $poolId: 'pool1', enabled: false, power_state: 'Unknown' },
  }
  const xo = { getObject: id => objects[id], getObjects: () => objects }
  const instance = plugin.default({ xo })
  instance.configure({ rules: [rule()] })

  const result = await instance.test({ targetHostId: 'h3' })
  assert.equal(result.wouldDo, 'none')
  assert.match(result.heldBackBecause, /power state is "Unknown"/)

  objects.h3.power_state = 'Halted'
  const halted = await instance.test({ targetHostId: 'h3' })
  assert.equal(halted.wouldDo, 'power-on')
  assert.equal(halted.heldBackBecause, null)
})
