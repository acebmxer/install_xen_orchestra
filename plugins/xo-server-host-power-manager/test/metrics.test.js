'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { getRunningHosts, getAverageCpuPercent, getVcpuRatio, getMemory } = require('../lib/metrics')

const GB = 1024 * 1024 * 1024

function makeXo(objects) {
  return { getObjects: () => objects }
}

test('getRunningHosts keeps only running, enabled hosts in the given pool', () => {
  const objects = {
    h1: { type: 'host', id: 'h1', $poolId: 'pool1', enabled: true, power_state: 'Running' },
    h2: { type: 'host', id: 'h2', $poolId: 'pool1', enabled: true, power_state: 'Halted' },
    h3: { type: 'host', id: 'h3', $poolId: 'pool1', enabled: false, power_state: 'Running' },
    h4: { type: 'host', id: 'h4', $poolId: 'pool2', enabled: true, power_state: 'Running' },
    vm1: { type: 'VM', id: 'vm1', $poolId: 'pool1', enabled: true, power_state: 'Running' },
  }

  const hosts = getRunningHosts(makeXo(objects), 'pool1')

  assert.deepEqual(
    hosts.map(host => host.id),
    ['h1']
  )
})

test('getMemory sums pool-wide free/total and tracks the tightest single host', () => {
  const hosts = [
    { memory: { size: 64 * GB, usage: 49 * GB } }, // 15GB free
    { memory: { size: 64 * GB, usage: 24 * GB } }, // 40GB free
  ]

  const result = getMemory(hosts)

  assert.equal(result.totalBytes, 128 * GB)
  assert.equal(result.freeBytes, 55 * GB)
  assert.equal(result.minFreeBytes, 15 * GB)
  assert.equal(result.minFreePercent, (15 / 64) * 100)
})

test('getMemory does not divide by zero when no hosts are running', () => {
  assert.deepEqual(getMemory([]), { totalBytes: 0, freeBytes: 0, minFreeBytes: 0, minFreePercent: 0 })
})

test('getMemory treats a single running host as both the pool total and the minimum', () => {
  const result = getMemory([{ memory: { size: 64 * GB, usage: 54 * GB } }])

  assert.equal(result.freeBytes, 10 * GB)
  assert.equal(result.minFreeBytes, 10 * GB)
  assert.equal(result.minFreePercent, (10 / 64) * 100)
})

test('getVcpuRatio divides running VMs\' vCPUs by physical cores of the given hosts', () => {
  const hosts = [
    { id: 'h1', cpus: { cores: 8 } },
    { id: 'h2', cpus: { cores: 8 } },
  ]
  const objects = {
    vm1: { type: 'VM', power_state: 'Running', $container: 'h1', CPUs: { number: 4 } },
    vm2: { type: 'VM', power_state: 'Running', $container: 'h2', CPUs: { number: 4 } },
    vm3: { type: 'VM', power_state: 'Halted', $container: 'h1', CPUs: { number: 100 } }, // not running: excluded
    vm4: { type: 'VM', power_state: 'Running', $container: 'other-host', CPUs: { number: 100 } }, // not one of the given hosts: excluded
  }

  const ratio = getVcpuRatio(makeXo(objects), hosts)

  assert.equal(ratio, 8 / 16)
})

test('getVcpuRatio returns 0 when the given hosts have no physical cores', () => {
  assert.equal(getVcpuRatio(makeXo({}), []), 0)
})

test('getAverageCpuPercent averages all core samples, then averages across hosts', async () => {
  const hosts = [{ id: 'h1' }, { id: 'h2' }]
  const xo = {
    getXapiHostStats: async host =>
      host.id === 'h1'
        ? { stats: { cpus: { 0: [10, 20], 1: [30, 40] } } } // avg 25
        : { stats: { cpus: { 0: [50, 50] } } }, // avg 50
  }

  assert.equal(await getAverageCpuPercent(xo, hosts), 37.5)
})

test('getAverageCpuPercent returns 0 when there are no hosts', async () => {
  assert.equal(await getAverageCpuPercent(makeXo({}), []), 0)
})

test('getAverageCpuPercent skips hosts with no core samples rather than treating them as 0', async () => {
  const hosts = [{ id: 'h1' }, { id: 'h2' }]
  const xo = {
    getXapiHostStats: async host => (host.id === 'h1' ? { stats: { cpus: {} } } : { stats: { cpus: { 0: [80] } } }),
  }

  assert.equal(await getAverageCpuPercent(xo, hosts), 80)
})
