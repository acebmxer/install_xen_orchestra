'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')
const { execFileSync } = require('node:child_process')

const { encryptLoginPassword } = require('../lib/aes-legacy')

const PASSPHRASE = 'nanokvm-sipeed-2024'

// Cross-checked against the system `openssl` binary rather than decrypting
// with this module's own code -- a bug shared between encrypt and a
// hand-rolled decrypt here could hide itself, but openssl is an independent
// implementation of the same "Salted__" / EVP_BytesToKey / AES-256-CBC
// scheme this module re-implements.
function opensslDecrypt(base64Ciphertext) {
  return execFileSync(
    'openssl',
    ['enc', '-d', '-aes-256-cbc', '-md', 'md5', '-pass', `pass:${PASSPHRASE}`, '-base64', '-A'],
    { input: base64Ciphertext }
  ).toString('utf8')
}

test('encryptLoginPassword output decrypts back to the original plaintext via openssl', () => {
  for (const plaintext of ['hunter2', '', 'unicode-✓-pässwörd', 'a'.repeat(200)]) {
    const ciphertext = encryptLoginPassword(plaintext)
    assert.equal(opensslDecrypt(ciphertext), plaintext)
  }
})

test('encryptLoginPassword uses a random salt, so the same input never repeats', () => {
  const a = encryptLoginPassword('hunter2')
  const b = encryptLoginPassword('hunter2')
  assert.notEqual(a, b)
  // ...but both still decrypt to the same plaintext.
  assert.equal(opensslDecrypt(a), 'hunter2')
  assert.equal(opensslDecrypt(b), 'hunter2')
})

test('encryptLoginPassword output starts with the OpenSSL "Salted__" marker', () => {
  const decoded = Buffer.from(encryptLoginPassword('hunter2'), 'base64')
  assert.equal(decoded.subarray(0, 8).toString('utf8'), 'Salted__')
})
