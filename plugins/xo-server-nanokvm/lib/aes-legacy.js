'use strict'

// NanoKVM's own web UI never sends login passwords in plaintext: before
// POSTing to /api/auth/login it encrypts the password with a fixed,
// publicly-known passphrase ("nanokvm-sipeed-2024", baked into every
// NanoKVM's firmware — see server/utils/encrypt.go in sipeed/NanoKVM). This
// is not meant to be a real secret; it only keeps the password out of the
// request body when the connection itself isn't already encrypted. HTTPS
// (as used here, via the reverse proxy) is what actually protects it.
//
// The scheme is the classic OpenSSL "Salted__" format (used by
// `openssl enc -aes-256-cbc`): an 8-byte random salt, MD5-based key/IV
// derivation (EVP_BytesToKey equivalent), AES-256-CBC with PKCS7 padding,
// the whole thing base64-encoded. This re-implements it with Node's builtin
// crypto module so the plugin has no extra runtime dependency.

const crypto = require('crypto')

const NANOKVM_LOGIN_PASSPHRASE = 'nanokvm-sipeed-2024'

function deriveKeyAndIv(passphrase, salt) {
  let digest = Buffer.alloc(0)
  let material = Buffer.alloc(0)
  const passphraseBuf = Buffer.from(passphrase, 'utf8')

  while (material.length < 48) {
    digest = crypto
      .createHash('md5')
      .update(Buffer.concat([digest, passphraseBuf, salt]))
      .digest()
    material = Buffer.concat([material, digest])
  }

  return {
    key: material.subarray(0, 32),
    iv: material.subarray(32, 48),
  }
}

// Encrypts `plaintext` the same way NanoKVM's web UI encrypts login
// passwords, so the result can be sent as-is in `LoginReq.Password`.
exports.encryptLoginPassword = function encryptLoginPassword(plaintext, passphrase = NANOKVM_LOGIN_PASSPHRASE) {
  const salt = crypto.randomBytes(8)
  const { key, iv } = deriveKeyAndIv(passphrase, salt)

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])

  return Buffer.concat([Buffer.from('Salted__', 'utf8'), salt, encrypted]).toString('base64')
}
