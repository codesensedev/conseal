// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * AES-256-GCM symmetric encryption.
 *
 * seal()   encrypts an ArrayBuffer with a CryptoKey, returning ciphertext + a
 *          random 96-bit IV. The 128-bit authentication tag is appended to the
 *          ciphertext by SubtleCrypto automatically.
 *
 * unseal() decrypts ciphertext given the same key and IV. Throws if the
 *          authentication tag fails — any tampering is detected.
 *
 * Callers convert File objects before passing in: await file.arrayBuffer()
 */

const IV_LENGTH = 12 // 96-bit IV — required for AES-GCM

/** Encrypts plaintext with AES-256-GCM. Returns ciphertext (with auth tag appended) and IV. */
export async function seal(
  key: CryptoKey,
  plaintext: ArrayBuffer,
  additionalData?: ArrayBuffer | Uint8Array
): Promise<{ ciphertext: ArrayBuffer; iv: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
  const algorithm: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 }
  if (additionalData !== undefined) algorithm.additionalData = additionalData as BufferSource
  const ciphertext = await crypto.subtle.encrypt(algorithm, key, plaintext)
  return { ciphertext, iv }
}

/** Decrypts AES-256-GCM ciphertext. Throws if the auth tag check fails. */
export async function unseal(
  key: CryptoKey,
  ciphertext: ArrayBuffer,
  iv: Uint8Array,
  additionalData?: ArrayBuffer | Uint8Array
): Promise<ArrayBuffer> {
  if (iv.byteLength !== IV_LENGTH) {
    throw new TypeError(`AES-GCM IV must be ${IV_LENGTH} bytes (96 bits), got ${iv.byteLength}`)
  }
  const algorithm: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 }
  if (additionalData !== undefined) algorithm.additionalData = additionalData as BufferSource
  return crypto.subtle.decrypt(algorithm, key, ciphertext)
}

/**
 * Generates a random AES-256-GCM CryptoKey.
 * Pass extractable: true when the key must be wrapped before storage (e.g. via wrapKey).
 */
export async function generateAesKey(extractable = false): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt']
  )
}

/**
 * Imports raw key bytes as an AES-256-GCM CryptoKey.
 * Pass extractable: true when the key must be wrapped before storage (e.g. via wrapKey).
 */
export async function importAesKey(raw: ArrayBuffer | Uint8Array, extractable = false): Promise<CryptoKey> {
  if (raw.byteLength !== 32) {
    throw new TypeError(`importAesKey: key must be 32 bytes (256 bits), got ${raw.byteLength}`)
  }
  return crypto.subtle.importKey(
    'raw',
    raw as BufferSource,
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt']
  )
}
