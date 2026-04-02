// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * Passcode-protected envelope encryption.
 *
 * Used for the secure drop flow: a sender seals data for a recipient who has
 * no Conseal account. A random DEK encrypts the data; the DEK is then wrapped
 * with the passcode via PBKDF2. Neither the ciphertext nor the wrapped key is
 * useful without the passcode.
 *
 * The caller stores the SealedEnvelope (or its JSON form) on the server.
 * The passcode travels via a separate channel (SMS, phone call, etc.).
 * An attacker who intercepts the server payload cannot decrypt without the passcode.
 *
 * sealEnvelope()   → encrypt + wrap. Returns a SealedEnvelope to store server-side.
 * unsealEnvelope() → unwrap DEK + decrypt. Requires the passcode.
 */

import { seal, unseal } from './aes'
import { wrapKey, unwrapKey } from './pbkdf2'
import { toBase64, fromBase64 } from './base64'

/** Encrypts plaintext and wraps the key with a passcode, returning a SealedEnvelope. */
export async function sealEnvelope(
  plaintext: ArrayBuffer,
  passcode: string
): Promise<SealedEnvelope> {
  // Generate a random DEK — extractable: true so wrapKey() can wrap it
  const dek = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )
  const { ciphertext, iv } = await seal(dek, plaintext)
  const { wrappedKey, salt } = await wrapKey(passcode, dek)
  return { ciphertext, iv, wrappedKey, salt }
}

/** Decrypts a SealedEnvelope using the passcode. Throws if the passcode is wrong. */
export async function unsealEnvelope(
  envelope: SealedEnvelope,
  passcode: string
): Promise<ArrayBuffer> {
  const dek = await unwrapKey(passcode, envelope.wrappedKey, envelope.salt)
  return unseal(dek, envelope.ciphertext, envelope.iv)
}

/** The fields produced by sealEnvelope(), ready for JSON serialisation. */
export interface SealedEnvelope {
  ciphertext: ArrayBuffer
  iv: Uint8Array
  wrappedKey: ArrayBuffer
  salt: Uint8Array
}

/**
 * Serialises a SealedEnvelope to a JSON string.
 * Each binary field is base64-encoded. Safe to store server-side or pass over text channels.
 */
export function encodeEnvelope(envelope: SealedEnvelope): string {
  return JSON.stringify({
    ciphertext: toBase64(envelope.ciphertext),
    iv:         toBase64(envelope.iv),
    wrappedKey: toBase64(envelope.wrappedKey),
    salt:       toBase64(envelope.salt),
  }, null, 2)
}

/**
 * Deserialises a JSON string produced by encodeEnvelope() back to a SealedEnvelope.
 * Throws SyntaxError if the string is not valid JSON.
 * Throws TypeError if required fields are missing or not strings.
 */
export function decodeEnvelope(json: string): SealedEnvelope {
  const p = JSON.parse(json) as Record<string, unknown>
  const required = ['ciphertext', 'iv', 'wrappedKey', 'salt'] as const
  for (const field of required) {
    if (typeof p[field] !== 'string') {
      throw new TypeError(`Invalid envelope: missing or invalid '${field}' field`)
    }
  }
  const validated = p as { ciphertext: string; iv: string; wrappedKey: string; salt: string }
  return {
    ciphertext: fromBase64(validated.ciphertext).buffer as ArrayBuffer,
    iv:         fromBase64(validated.iv),
    wrappedKey: fromBase64(validated.wrappedKey).buffer as ArrayBuffer,
    salt:       fromBase64(validated.salt),
  }
}
