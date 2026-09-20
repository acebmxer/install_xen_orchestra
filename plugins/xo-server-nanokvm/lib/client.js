'use strict'

const { encryptLoginPassword } = require('./aes-legacy')

// NanoKVM issues a JWT session cookie on login (lifetime is admin-configurable
// on the device, jwt.refreshTokenDuration, default ~31 days). We cache it per
// device and only log in again once the server actually rejects it (HTTP
// 401), rather than guessing at its lifetime.

class NanoKvmError extends Error {
  constructor(message, { cause } = {}) {
    super(message, { cause })
    this.name = 'NanoKvmError'
  }
}
exports.NanoKvmError = NanoKvmError

class NanoKvmClient {
  // `device` is one entry of the plugin's `devices` configuration array:
  // { label, baseUrl, username, password, hostId }
  constructor(device) {
    this._baseUrl = device.baseUrl.replace(/\/+$/, '')
    this._username = device.username
    this._password = device.password
    this._label = device.label || this._baseUrl
    this._cookie = null
    this._loginPromise = null
  }

  async _request(path, { method = 'GET', body, requireSession = true, retrying = false } = {}) {
    const headers = { Accept: 'application/json' }
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json'
    }
    if (requireSession) {
      await this._ensureSession()
      headers.Cookie = this._cookie
    }

    const response = await fetch(this._baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    })

    // A previously valid session can be revoked server-side (password
    // change, logout-elsewhere, expiry). Retry once with a fresh login
    // before giving up.
    if (requireSession && response.status === 401 && !retrying) {
      this._cookie = null
      return this._request(path, { method, body, requireSession, retrying: true })
    }

    return this._parseResponse(response, path)
  }

  async _parseResponse(response, path) {
    let payload
    try {
      payload = await response.json()
    } catch (error) {
      throw new NanoKvmError(`${this._label}: invalid response from ${path} (HTTP ${response.status})`, {
        cause: error,
      })
    }

    if (!response.ok || (typeof payload.code === 'number' && payload.code !== 0)) {
      const message = payload.message || payload.msg || `HTTP ${response.status}`
      throw new NanoKvmError(`${this._label}: ${path} failed: ${message}`)
    }

    return payload.data
  }

  async _ensureSession() {
    if (this._cookie !== null) {
      return
    }
    // Coalesce concurrent callers into a single login attempt.
    if (this._loginPromise === null) {
      this._loginPromise = this._login().finally(() => {
        this._loginPromise = null
      })
    }
    return this._loginPromise
  }

  async _login() {
    // The server URL-decodes this field before decrypting it
    // (DecodeDecrypt -> url.QueryUnescape, see server/utils/encrypt.go), so
    // the encrypted payload has to be URL-encoded here or a '+' in the
    // base64 output gets silently turned into a space server-side,
    // corrupting the ciphertext. Confirmed against the real device: without
    // this, login only succeeds when the random salt happens to produce a
    // '+'-free string (~40% of the time), which looked like flakiness until
    // traced to this.
    const response = await fetch(this._baseUrl + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        username: this._username,
        password: encodeURIComponent(encryptLoginPassword(this._password)),
      }),
    })

    const setCookie = response.headers.get('set-cookie')
    if (!response.ok || !setCookie) {
      let message = `HTTP ${response.status}`
      try {
        const payload = await response.json()
        message = payload.message || payload.msg || message
      } catch {
        // ignore — fall back to the HTTP status above
      }
      throw new NanoKvmError(`${this._label}: login failed: ${message}`)
    }

    // Only the cookie's name=value pair should be resent, not the
    // Path/HttpOnly/SameSite attributes also present in Set-Cookie.
    this._cookie = setCookie.split(';', 1)[0]
  }

  // Presses the power or reset button for `durationMs` (NanoKVM default is
  // 800ms, matching a normal tap of a physical button). A short press
  // powers on a host that's off, or asks a running host's OS to shut down
  // gracefully (ACPI power button signal) — the same as someone walking up
  // and tapping the case button. NanoKVM does not distinguish "on" from
  // "off": it only knows how to press the button.
  async pressPower({ durationMs = 800 } = {}) {
    await this._request('/api/vm/gpio', { method: 'POST', body: { type: 'power', duration: durationMs } })
  }

  async pressReset({ durationMs = 800 } = {}) {
    await this._request('/api/vm/gpio', { method: 'POST', body: { type: 'reset', duration: durationMs } })
  }

  // Reads the host's power LED. This reflects the NanoKVM's own GPIO read
  // of the host's power LED pins, not XCP-ng/XAPI state — it's only useful
  // as a quick "is it physically powered" sanity check while XAPI is
  // unreachable (e.g. right after a power-on, before the host has booted).
  async getPowerLedOn() {
    const data = await this._request('/api/vm/gpio', { method: 'GET' })
    return Boolean(data && data.pwr)
  }
}
exports.NanoKvmClient = NanoKvmClient
