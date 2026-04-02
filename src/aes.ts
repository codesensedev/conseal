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

/** Encrypts plaintext with AES-256-GCM. Returns ciphertext (with auth tag appended) and IV. */
export async function seal(
  key: CryptoKey,
  plaintext: ArrayBuffer
): Promise<{ ciphertext: ArrayBuffer; iv: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(12)) // 96-bit IV — required for AES-GCM
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 }, key, plaintext)
  return { ciphertext, iv }
}

/** Decrypts AES-256-GCM ciphertext. Throws if the auth tag check fails. */
export async function unseal(
  key: CryptoKey,
  ciphertext: ArrayBuffer,
  iv: Uint8Array
): Promise<ArrayBuffer> {
  if (iv.byteLength !== 12) {
    throw new TypeError(`AES-GCM IV must be 12 bytes (96 bits), got ${iv.byteLength}`)
  }
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 }, key, ciphertext)
}
