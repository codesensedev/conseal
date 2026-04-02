/**
 * SHA-256 digest.
 *
 * Thin wrapper around SubtleCrypto.digest for the hash function used throughout
 * this library — key fingerprinting, content hashing, and integrity checks.
 */

/** Returns the SHA-256 hash of the input data as an ArrayBuffer. */
export async function digest(data: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', data as BufferSource)
}
