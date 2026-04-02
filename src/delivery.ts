/**
 * Anonymous one-time delivery encryption.
 *
 * Used for the secure drop flow: a sender seals a file for a recipient who has
 * no Conseal account. A random DEK encrypts the file; the DEK is then wrapped
 * with the passcode via PBKDF2. Neither the ciphertext nor the wrapped key is
 * useful without the passcode.
 *
 * The caller stores { ciphertext, iv, wrappedKey, salt } on the server.
 * The passcode travels via a separate channel (SMS, phone call, etc.).
 * An attacker who intercepts the server payload cannot decrypt without the passcode.
 *
 * sealDelivery()   → encrypt + wrap. Returns everything to store server-side.
 * unsealDelivery() → unwrap DEK + decrypt. Requires the passcode.
 */

import { seal, unseal } from './aes'
import { wrapKey, unwrapKey } from './pbkdf2'

/** Encrypts plaintext for anonymous delivery protected by a passcode. */
export async function sealDelivery(
  plaintext: ArrayBuffer,
  passcode: string
): Promise<{ ciphertext: ArrayBuffer; iv: Uint8Array; wrappedKey: ArrayBuffer; salt: Uint8Array }> {
  // Generate a random DEK for this delivery — extractable: true so wrapKey() can wrap it
  const dek = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )
  const { ciphertext, iv } = await seal(dek, plaintext)
  const { wrappedKey, salt } = await wrapKey(passcode, dek)
  return { ciphertext, iv, wrappedKey, salt }
}

/** Decrypts a delivery payload using the passcode. Throws if the passcode is wrong. */
export async function unsealDelivery(
  ciphertext: ArrayBuffer,
  iv: Uint8Array,
  wrappedKey: ArrayBuffer,
  salt: Uint8Array,
  passcode: string
): Promise<ArrayBuffer> {
  const dek = await unwrapKey(passcode, wrappedKey, salt)
  return unseal(dek, ciphertext, iv)
}
