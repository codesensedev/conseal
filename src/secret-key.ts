// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * 128-bit Secret Key — second factor for AEK wrapping.
 *
 * generateSecretKey()              generates a random 128-bit secret key. Call once
 *                                  at account setup and store device-side (localStorage)
 *                                  plus an offline copy for recovery.
 *
 * combinePassphraseAndSecretKey()  SHA-256 hashes passphrase + ':' + base64(secretKey)
 *                                  into a 64-char hex string used as the PBKDF2 input.
 *                                  Neither factor is recoverable from the combined value.
 */

import { digest } from './digest'
import { toBase64 } from './base64'

/** Generates a random 128-bit (16-byte) secret key. */
export function generateSecretKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16))
}

/**
 * Combines a passphrase and secret key into a single opaque string for PBKDF2.
 * SHA-256(passphrase + ':' + base64(secretKey)), hex-encoded.
 */
export async function combinePassphraseAndSecretKey(
  passphrase: string,
  secretKey: Uint8Array
): Promise<string> {
  const input = `${passphrase}:${toBase64(secretKey)}`
  const hash = await digest(new TextEncoder().encode(input))
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}
