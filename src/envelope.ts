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
  // Raw DEK bytes live briefly in memory inside wrapKey; JavaScript provides no
  // reliable way to zero them, but they are never returned or stored.
  const { wrappedKey, salt } = await wrapKey(passcode, dek)
  return { version: 1, ciphertext, iv, wrappedKey, salt }
}

/** Decrypts a SealedEnvelope using the passcode. Throws if the passcode is wrong. */
export async function unsealEnvelope(
  envelope: SealedEnvelope,
  passcode: string
): Promise<ArrayBuffer> {
  const dek = await unwrapKey(passcode, envelope.wrappedKey, envelope.salt)
  return unseal(dek, envelope.ciphertext, envelope.iv)
}

/**
 * The in-memory representation produced by sealEnvelope().
 *
 * **Not directly JSON-serialisable.** ArrayBuffer and Uint8Array fields are
 * silently lost or corrupted by JSON.stringify. Use encodeEnvelope() to produce
 * a JSON string and decodeEnvelope() to reconstruct this type from one.
 */
export interface SealedEnvelope {
  /** Format version — always 1 for envelopes produced by this library. */
  version: 1
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
    version:    envelope.version,
    ciphertext: toBase64(envelope.ciphertext),
    iv:         toBase64(envelope.iv),
    wrappedKey: toBase64(envelope.wrappedKey),
    salt:       toBase64(envelope.salt),
  })
}

/**
 * Deserialises a JSON string produced by encodeEnvelope() back to a SealedEnvelope.
 * Throws SyntaxError if the string is not valid JSON.
 * Throws TypeError if required fields are missing, the wrong type, or the version is unsupported.
 */
export function decodeEnvelope(json: string): SealedEnvelope {
  const p = JSON.parse(json) as Record<string, unknown>

  if (p['version'] !== 1) {
    throw new TypeError(`Invalid envelope: unsupported or missing 'version' field (got ${JSON.stringify(p['version'])})`)
  }

  const binaryFields = ['ciphertext', 'iv', 'wrappedKey', 'salt'] as const
  for (const field of binaryFields) {
    if (typeof p[field] !== 'string') {
      throw new TypeError(`Invalid envelope: missing or invalid '${field}' field`)
    }
  }

  const validated = p as { ciphertext: string; iv: string; wrappedKey: string; salt: string }

  // Validate base64 content before decoding to give a clear error on malformed input
  for (const field of binaryFields) {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(validated[field])) {
      throw new TypeError(`Invalid envelope: '${field}' is not valid base64`)
    }
  }

  return {
    version:    1,
    ciphertext: fromBase64(validated.ciphertext).buffer as ArrayBuffer,
    iv:         fromBase64(validated.iv),
    wrappedKey: fromBase64(validated.wrappedKey).buffer as ArrayBuffer,
    salt:       fromBase64(validated.salt),
  }
}
