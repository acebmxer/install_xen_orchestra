'use strict'

// xo-server-nanokvm
//
// Connection/credentials plugin for hosts fitted with a Sipeed NanoKVM
// device. This plugin's only job is talking to NanoKVM's REST API (login +
// power/reset button press) and exposing that as a small "host power
// provider" that other plugins — xo-server-host-power-manager in
// particular — can look up and call, the same way a Dell iDRAC or HP iLO
// is used through XO's own built-in host power-on mode.
//
// It deliberately does not decide *when* to power a host on — see
// xo-server-host-power-manager for the policy (CPU/memory thresholds).

const { NanoKvmClient } = require('./lib/client')

exports.configurationSchema = {
  type: 'object',
  description:
    'One entry per NanoKVM device. A NanoKVM is normally wired to a single host\'s power/reset header, so add one entry per host it controls. Devices can share the same username/password, or each use its own — both work, since every entry is independent.',
  properties: {
    devices: {
      type: 'array',
      title: 'NanoKVM devices',
      items: {
        type: 'object',
        title: 'Device',
        properties: {
          label: {
            type: 'string',
            title: 'Label',
            description: 'A name to identify this device in logs, e.g. "host NanoKVM".',
          },
          baseUrl: {
            type: 'string',
            title: 'Base URL',
            description: 'e.g. https://host.example.com (include the scheme, no trailing slash needed).',
          },
          username: {
            type: 'string',
            title: 'Username',
            description:
              'Use a dedicated account with the "user" role (Settings > Account, firmware 2.5.1+) — power/reset does not require "admin". On older firmware without multi-user support, use the admin account instead.',
          },
          password: {
            type: 'string',
            title: 'Password',
          },
          hostId: {
            type: 'string',
            title: 'XO host UUID',
            description: "The UUID of the XCP-ng host this device's power/reset header is wired to.",
          },
        },
        required: ['label', 'baseUrl', 'username', 'password', 'hostId'],
      },
    },
  },
  required: ['devices'],
}

exports.testSchema = {
  type: 'object',
  properties: {
    hostId: {
      type: 'string',
      title: 'XO host UUID',
      description: 'Which configured device to test, matched by its hostId.',
    },
  },
  required: ['hostId'],
}

const PROVIDER_ID = 'nanokvm'

exports.default = function ({ xo }) {
  let devicesByHostId = new Map()

  const provider = {
    id: PROVIDER_ID,
    label: 'NanoKVM',

    supportsHost(hostId) {
      return devicesByHostId.has(hostId)
    },

    // Presses the power button. NanoKVM can't distinguish "the host is off"
    // from "the host is on" itself — this is used for power-on, where the
    // caller already knows the host is off.
    async powerOn(hostId) {
      const entry = devicesByHostId.get(hostId)
      if (entry === undefined) {
        throw new Error(`xo-server-nanokvm: no device configured for host ${hostId}`)
      }
      await entry.client.pressPower()
    },

    // Best-effort local signal only (reads the NanoKVM's own GPIO power LED
    // pin) — callers should treat XAPI/XO host state as authoritative and
    // use this only while a host is booting and not yet reachable there.
    async getPowerState(hostId) {
      const entry = devicesByHostId.get(hostId)
      if (entry === undefined) {
        return 'unknown'
      }
      try {
        return (await entry.client.getPowerLedOn()) ? 'on' : 'off'
      } catch {
        return 'unknown'
      }
    },
  }

  return {
    configure(configuration) {
      const nextDevicesByHostId = new Map()
      for (const device of (configuration && configuration.devices) || []) {
        nextDevicesByHostId.set(device.hostId, { device, client: new NanoKvmClient(device) })
      }
      devicesByHostId = nextDevicesByHostId
    },

    load() {
      if (xo.customHostPowerProviders === undefined) {
        xo.customHostPowerProviders = new Map()
      }
      xo.customHostPowerProviders.set(PROVIDER_ID, provider)
    },

    unload() {
      if (xo.customHostPowerProviders !== undefined) {
        xo.customHostPowerProviders.delete(PROVIDER_ID)
      }
    },

    // Logs in and reads GPIO state without pressing anything, to check the
    // configured URL/credentials are correct.
    async test({ hostId }) {
      const entry = devicesByHostId.get(hostId)
      if (entry === undefined) {
        throw new Error(`xo-server-nanokvm: no device configured for host ${hostId}`)
      }
      await entry.client.getPowerLedOn()
    },
  }
}
