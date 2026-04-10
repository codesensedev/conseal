// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * 128-bit Secret Key — second factor for AEK wrapping.
 *
 * generateSecretKey()              generates a random 128-bit secret key. Call once
 *                                  at account setup and store device-side (localStorage)
 *                                  plus an offline copy for recovery.
 *
 * combinePassphraseAndSecretKey()  HMAC-SHA-256(key=secretKey, msg=passphrase),
 *                                  hex-encoded. The secretKey is used as the HMAC key
 *                                  and the passphrase as the message, which is the
 *                                  standard construction for combining two inputs.
 *                                  Neither factor is recoverable from the result.
 *                                  The output is fed into PBKDF2 as the password.
 */

/** Generates a random 128-bit (16-byte) secret key. */
export function generateSecretKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16))
}

/**
 * Combines a passphrase and secret key into a single opaque string for PBKDF2.
 * HMAC-SHA-256(key=secretKey, msg=passphrase), hex-encoded.
 *
 * Using HMAC with the secretKey as the key is the standard construction for
 * combining two inputs — it avoids length-extension concerns and provides
 * cryptographic binding of both factors.
 */
export async function combinePassphraseAndSecretKey(
  passphrase: string,
  secretKey: Uint8Array
): Promise<string> {
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    secretKey.buffer.slice(secretKey.byteOffset, secretKey.byteOffset + secretKey.byteLength) as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const mac = await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(passphrase))
  return Array.from(new Uint8Array(mac))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}
