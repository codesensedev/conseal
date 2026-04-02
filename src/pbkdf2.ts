/**
 * PBKDF2-SHA256 key derivation and AES-KW key wrapping.
 *
 * wrapKey()   derives a wrapping key from a passphrase + random salt, then uses
 *             AES-KW to wrap the target CryptoKey. Salt must be stored alongside
 *             the wrapped key — it is not secret.
 *
 * unwrapKey() reverses the process. Always returns extractable: false — the
 *             unwrapped key is safe to store in IndexedDB and use for encrypt/decrypt.
 *
 * rekey()     changes the passphrase without touching any encrypted content.
 *             Unwraps the AEK with the old passphrase, re-wraps with the new one.
 *             The AEK itself never changes.
 *
 * PBKDF2 parameters: 600,000 iterations, SHA-256, 128-bit random salt per call.
 * This is intentionally slow — it is the defence against offline brute-force if
 * the wrapped key is ever leaked.
 */

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

/** Wraps a CryptoKey with a passphrase. The input key must have extractable: true. */
export async function wrapKey(
  passphrase: string,
  key: CryptoKey
): Promise<{ wrappedKey: ArrayBuffer; salt: Uint8Array }> {
  if (!key.extractable) {
    throw new Error('wrapKey: key must be extractable (extractable: true)')
  }
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))
  const wrappingKey = await deriveWrappingKey(passphrase, salt)
  const wrappedKey = await crypto.subtle.wrapKey('raw', key, wrappingKey, 'AES-KW')
  return { wrappedKey, salt }
}

/** Unwraps a CryptoKey. Always returns extractable: false. */
export async function unwrapKey(
  passphrase: string,
  wrappedKey: ArrayBuffer,
  salt: Uint8Array
): Promise<CryptoKey> {
  const wrappingKey = await deriveWrappingKey(passphrase, salt)
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
 * Internally unwraps with extractable: true so the key can be immediately re-wrapped.
 */
export async function rekey(
  oldPassphrase: string,
  newPassphrase: string,
  wrappedKey: ArrayBuffer,
  salt: Uint8Array
): Promise<{ wrappedKey: ArrayBuffer; salt: Uint8Array }> {
  // Unwrap with extractable: true — required to re-wrap immediately after
  const oldWrappingKey = await deriveWrappingKey(oldPassphrase, salt)
  const aek = await crypto.subtle.unwrapKey(
    'raw',
    wrappedKey,
    oldWrappingKey,
    'AES-KW',
    { name: 'AES-GCM', length: 256 },
    true, // extractable: true — needed so wrapKey() can wrap it again
    ['encrypt', 'decrypt']
  )
  return wrapKey(newPassphrase, aek)
}
