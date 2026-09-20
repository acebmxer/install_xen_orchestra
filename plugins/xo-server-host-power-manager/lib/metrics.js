'use strict'

// Pool-wide metrics used to decide whether a managed ("extra") host is
// needed. All metrics are computed only from the hosts that are currently
// running and enabled in the pool, excluding the managed host itself — that
// host may be off, and its own (lack of) load must not affect the decision
// to power it on.

function getAlwaysOnHosts(xo, poolId, excludeHostId) {
  const hosts = []
  for (const object of Object.values(xo.getObjects())) {
    if (
      object.type === 'host' &&
      object.$poolId === poolId &&
      object.id !== excludeHostId &&
      object.enabled === true &&
      object.power_state === 'Running'
    ) {
      hosts.push(object)
    }
  }
  return hosts
}
exports.getAlwaysOnHosts = getAlwaysOnHosts

// Average CPU utilization (0-100) across all cores of all given hosts, over
// the most recent seconds-granularity samples XAPI has.
//
// `stats.cpus` comes back keyed by core index ("0", "1", ...) rather than as
// a true array, so it's read with Object.values() rather than a for..of —
// confirmed against a real host's /rest/v0/hosts/<id>/stats response, which
// also confirmed each point is already a 0-100 percentage (values were seen
// up to ~14 on an idle-ish host), not a 0-1 fraction that needs scaling.
async function getAverageCpuPercent(xo, hosts) {
  if (hosts.length === 0) {
    return 0
  }

  const perHostAverages = await Promise.all(
    hosts.map(async host => {
      const { stats } = await xo.getXapiHostStats(host, 'seconds')
      const cores = stats.cpus ? Object.values(stats.cpus) : []
      if (cores.length === 0) {
        return undefined
      }
      let sum = 0
      let count = 0
      for (const core of cores) {
        for (const point of core) {
          if (point != null) {
            sum += point
            count++
          }
        }
      }
      return count === 0 ? undefined : sum / count
    })
  )

  const valid = perHostAverages.filter(value => value !== undefined)
  if (valid.length === 0) {
    return 0
  }
  return valid.reduce((a, b) => a + b, 0) / valid.length
}
exports.getAverageCpuPercent = getAverageCpuPercent

// Total allocated vCPUs (of running VMs) divided by total physical cores,
// across the given hosts.
function getVcpuRatio(xo, hosts) {
  const hostIds = new Set(hosts.map(host => host.id))
  const totalPcpus = hosts.reduce((sum, host) => sum + (host.cpus?.cores || 0), 0)
  if (totalPcpus === 0) {
    return 0
  }

  let totalVcpus = 0
  for (const object of Object.values(xo.getObjects())) {
    if (object.type === 'VM' && object.power_state === 'Running' && hostIds.has(object.$container)) {
      totalVcpus += object.CPUs?.number || 0
    }
  }

  return totalVcpus / totalPcpus
}
exports.getVcpuRatio = getVcpuRatio

// { totalBytes, freeBytes } summed across the given hosts' live memory
// state (not historical stats — this is XAPI's current view).
function getMemory(hosts) {
  let totalBytes = 0
  let freeBytes = 0
  for (const host of hosts) {
    const size = host.memory?.size || 0
    const usage = host.memory?.usage || 0
    totalBytes += size
    freeBytes += size - usage
  }
  return { totalBytes, freeBytes }
}
exports.getMemory = getMemory
