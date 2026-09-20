'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { NanoKvmClient } = require('../lib/client')

function device(overrides = {}) {
  return { baseUrl: 'https://kvm.example.com', username: 'u', password: 'p', label: 'my-kvm', ...overrides }
}

test('pressPower logs in, then presses the button, sending only the cookie name=value', async t => {
  const calls = []
  const originalFetch = global.fetch
  global.fetch = async (url, options) => {
    calls.push({ url, options })
    if (url.endsWith('/api/auth/login')) {
      return new Response(JSON.stringify({ code: 0 }), {
        status: 200,
        headers: { 'set-cookie': 'session=abc123; Path=/; HttpOnly; SameSite=Lax' },
      })
    }
    assert.equal(options.headers.Cookie, 'session=abc123')
    return new Response(JSON.stringify({ code: 0, data: null }), { status: 200 })
  }
  t.after(() => {
    global.fetch = originalFetch
  })

  const client = new NanoKvmClient(device())
  await client.pressPower()

  assert.equal(calls.length, 2)
  assert.equal(calls[1].url, 'https://kvm.example.com/api/vm/gpio')
  assert.deepEqual(JSON.parse(calls[1].options.body), { type: 'power', duration: 800 })
})

test('pressReset sends type "reset" with a custom duration', async t => {
  const calls = []
  const originalFetch = global.fetch
  global.fetch = async (url, options) => {
    calls.push({ url, options })
    if (url.endsWith('/api/auth/login')) {
      return new Response(JSON.stringify({ code: 0 }), { status: 200, headers: { 'set-cookie': 'session=abc; Path=/' } })
    }
    return new Response(JSON.stringify({ code: 0, data: null }), { status: 200 })
  }
  t.after(() => {
    global.fetch = originalFetch
  })

  const client = new NanoKvmClient(device())
  await client.pressReset({ durationMs: 3000 })

  assert.deepEqual(JSON.parse(calls[1].options.body), { type: 'reset', duration: 3000 })
})

test('a 401 on an authenticated request triggers exactly one re-login and retry', async t => {
  const calls = []
  let loginCount = 0
  const originalFetch = global.fetch
  global.fetch = async (url, options) => {
    calls.push({ url, options })
    if (url.endsWith('/api/auth/login')) {
      loginCount++
      return new Response(JSON.stringify({ code: 0 }), {
        status: 200,
        headers: { 'set-cookie': `session=cookie${loginCount}; Path=/` },
      })
    }
    const attemptNumber = calls.filter(c => c.url.endsWith('/api/vm/gpio')).length
    if (attemptNumber === 1) {
      return new Response(JSON.stringify({ message: 'expired' }), { status: 401 })
    }
    return new Response(JSON.stringify({ code: 0, data: { pwr: true } }), { status: 200 })
  }
  t.after(() => {
    global.fetch = originalFetch
  })

  const client = new NanoKvmClient(device())
  const on = await client.getPowerLedOn()

  assert.equal(on, true)
  assert.equal(loginCount, 2)
  const gpioCalls = calls.filter(c => c.url.endsWith('/api/vm/gpio'))
  assert.equal(gpioCalls.length, 2)
  assert.equal(gpioCalls[0].options.headers.Cookie, 'session=cookie1')
  assert.equal(gpioCalls[1].options.headers.Cookie, 'session=cookie2')
})

test('a failed login throws NanoKvmError with the server message and device label', async t => {
  const originalFetch = global.fetch
  global.fetch = async () => new Response(JSON.stringify({ message: 'invalid credentials' }), { status: 401 })
  t.after(() => {
    global.fetch = originalFetch
  })

  const client = new NanoKvmClient(device({ password: 'wrong' }))
  await assert.rejects(
    () => client.pressPower(),
    error => {
      assert.equal(error.name, 'NanoKvmError')
      assert.match(error.message, /invalid credentials/)
      assert.match(error.message, /my-kvm/)
      return true
    }
  )
})

test('a non-zero response code on an authenticated request throws with the server-reported message', async t => {
  const originalFetch = global.fetch
  global.fetch = async url => {
    if (url.endsWith('/api/auth/login')) {
      return new Response(JSON.stringify({ code: 0 }), { status: 200, headers: { 'set-cookie': 'session=abc; Path=/' } })
    }
    return new Response(JSON.stringify({ code: 1, msg: 'gpio busy' }), { status: 200 })
  }
  t.after(() => {
    global.fetch = originalFetch
  })

  const client = new NanoKvmClient(device())
  await assert.rejects(() => client.pressPower(), /gpio busy/)
})

test('getPowerLedOn reads the pwr field, defaulting to false when absent', async t => {
  const originalFetch = global.fetch
  global.fetch = async url => {
    if (url.endsWith('/api/auth/login')) {
      return new Response(JSON.stringify({ code: 0 }), { status: 200, headers: { 'set-cookie': 'session=abc; Path=/' } })
    }
    return new Response(JSON.stringify({ code: 0, data: {} }), { status: 200 })
  }
  t.after(() => {
    global.fetch = originalFetch
  })

  const client = new NanoKvmClient(device())
  assert.equal(await client.getPowerLedOn(), false)
})

test('a trailing slash on baseUrl is stripped before building request URLs', async t => {
  const calls = []
  const originalFetch = global.fetch
  global.fetch = async url => {
    calls.push(url)
    if (url.endsWith('/api/auth/login')) {
      return new Response(JSON.stringify({ code: 0 }), { status: 200, headers: { 'set-cookie': 'session=abc; Path=/' } })
    }
    return new Response(JSON.stringify({ code: 0, data: { pwr: false } }), { status: 200 })
  }
  t.after(() => {
    global.fetch = originalFetch
  })

  const client = new NanoKvmClient(device({ baseUrl: 'https://kvm.example.com///' }))
  await client.getPowerLedOn()

  assert.equal(calls[0], 'https://kvm.example.com/api/auth/login')
  assert.ok(calls.every(url => !url.includes('///')))
})

test('concurrent requests coalesce into a single login attempt', async t => {
  let loginCalls = 0
  const originalFetch = global.fetch
  global.fetch = async url => {
    if (url.endsWith('/api/auth/login')) {
      loginCalls++
      await new Promise(resolve => setTimeout(resolve, 10))
      return new Response(JSON.stringify({ code: 0 }), { status: 200, headers: { 'set-cookie': 'session=abc; Path=/' } })
    }
    return new Response(JSON.stringify({ code: 0, data: { pwr: false } }), { status: 200 })
  }
  t.after(() => {
    global.fetch = originalFetch
  })

  const client = new NanoKvmClient(device())
  await Promise.all([client.getPowerLedOn(), client.getPowerLedOn()])

  assert.equal(loginCalls, 1)
})
