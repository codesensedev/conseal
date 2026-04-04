// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * PBKDF2-SHA256 key derivation and AES-KW key wrapping.
 *
 * wrapKey()        derives a wrapping key from a passphrase + random salt, then uses
 *                  AES-KW to wrap the target CryptoKey. Salt must be stored alongside
 *                  the wrapped key — it is not secret.
 *
 * unwrapKey()      reverses the process. Always returns extractable: false — the
 *                  unwrapped key is safe to store in IndexedDB and use for encrypt/decrypt.
 *
 * rekey()          changes the passphrase without touching any encrypted content.
 *                  Unwraps the AEK with the old passphrase, re-wraps with the new one.
 *                  The AEK itself never changes.
 *
 * rekeySecretKey() rotates the Secret Key while keeping the passphrase the same.
 *                  Use this only when the Secret Key is compromised — it is a rare
 *                  operation equivalent to a full account re-setup.
 *
 * All four functions accept an optional secretKey (Uint8Array). When provided,
 * the passphrase is combined with the Secret Key via SHA-256 before PBKDF2 runs.
 * Existing callers that pass no secretKey are unaffected.
 *
 * PBKDF2 parameters: 600,000 iterations, SHA-256, 128-bit random salt per call.
 * This is intentionally slow — it is the defence against offline brute-force if
 * the wrapped key is ever leaked.
 */

import { combinePassphraseAndSecretKey } from './secret-key'

const ITERATIONS = 600_000
const SALT_LENGTH = 16 // 128-bit salt

async function deriveWrappingKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations: ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  )
}

async function resolvePassphrase(passphrase: string, secretKey?: Uint8Array): Promise<string> {
  return secretKey ? combinePassphraseAndSecretKey(passphrase, secretKey) : passphrase
}

/** Wraps a CryptoKey with a passphrase (and optional Secret Key). The input key must have extractable: true. */
export async function wrapKey(
  passphrase: string,
  key: CryptoKey,
  secretKey?: Uint8Array
): Promise<{ wrappedKey: ArrayBuffer; salt: Uint8Array }> {
  if (!key.extractable) {
    throw new Error('wrapKey: key must be extractable (extractable: true)')
  }
  const effective = await resolvePassphrase(passphrase, secretKey)
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))
  const wrappingKey = await deriveWrappingKey(effective, salt)
  const wrappedKey = await crypto.subtle.wrapKey('raw', key, wrappingKey, 'AES-KW')
  return { wrappedKey, salt }
}

/** Unwraps a CryptoKey. Always returns extractable: false. */
export async function unwrapKey(
  passphrase: string,
  wrappedKey: ArrayBuffer,
  salt: Uint8Array,
  secretKey?: Uint8Array
): Promise<CryptoKey> {
  const effective = await resolvePassphrase(passphrase, secretKey)
  const wrappingKey = await deriveWrappingKey(effective, salt)
  return crypto.subtle.unwrapKey(
    'raw',
    wrappedKey,
    wrappingKey,
    'AES-KW',
    { name: 'AES-GCM', length: 256 },
    false, // extractable: false — safe for IndexedDB storage
    ['encrypt', 'decrypt']
  )
}

/**
 * Changes the passphrase protecting the AEK without re-encrypting any content.
 * The Secret Key (if any) stays the same — it is used on both the unwrap and re-wrap sides.
 */
export async function rekey(
  oldPassphrase: string,
  newPassphrase: string,
  wrappedKey: ArrayBuffer,
  salt: Uint8Array,
  secretKey?: Uint8Array
): Promise<{ wrappedKey: ArrayBuffer; salt: Uint8Array }> {
  const effectiveOld = await resolvePassphrase(oldPassphrase, secretKey)
  const oldWrappingKey = await deriveWrappingKey(effectiveOld, salt)
  const aek = await crypto.subtle.unwrapKey(
    'raw',
    wrappedKey,
    oldWrappingKey,
    'AES-KW',
    { name: 'AES-GCM', length: 256 },
    true, // extractable: true — needed so wrapKey() can wrap it again
    ['encrypt', 'decrypt']
  )
  return wrapKey(newPassphrase, aek, secretKey)
}

/**
 * Rotates the Secret Key while keeping the passphrase the same.
 * Use only when the Secret Key is compromised — this is a rare, heavyweight operation.
 * Unwraps with passphrase + oldSecretKey, re-wraps with passphrase + newSecretKey.
 *
 * @param passphrase  - the passphrase (unchanged)
 * @param oldSecretKey - the current Secret Key (used to unwrap)
 * @param newSecretKey - the replacement Secret Key (used to re-wrap)
 * @param wrappedKey   - the currently wrapped AEK
 * @param salt         - the salt used when the AEK was wrapped
 */
export async function rekeySecretKey(
  passphrase: string,
  oldSecretKey: Uint8Array,
  newSecretKey: Uint8Array,
  wrappedKey: ArrayBuffer,
  salt: Uint8Array
): Promise<{ wrappedKey: ArrayBuffer; salt: Uint8Array }> {
  if (
    oldSecretKey.length === newSecretKey.length &&
    oldSecretKey.every((b, i) => b === newSecretKey[i])
  ) {
    throw new Error('rekeySecretKey: oldSecretKey and newSecretKey must be different')
  }
  const effectiveOld = await resolvePassphrase(passphrase, oldSecretKey)
  const oldWrappingKey = await deriveWrappingKey(effectiveOld, salt)
  const aek = await crypto.subtle.unwrapKey(
    'raw',
    wrappedKey,
    oldWrappingKey,
    'AES-KW',
    { name: 'AES-GCM', length: 256 },
    true, // extractable: true — needed so wrapKey() can wrap it again
    ['encrypt', 'decrypt']
  )
  return wrapKey(passphrase, aek, newSecretKey)
}
