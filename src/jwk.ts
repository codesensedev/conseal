/**
 * JWK serialisation for public keys.
 *
 * exportPublicKeyAsJwk() serialises a CryptoKey to a JSON Web Key — used when
 * registering a public key with the Conseal identity registry.
 *
 * importPublicKeyFromJwk() deserialises a JWK back to a CryptoKey — used when
 * loading a recipient's public key before encrypting a message.
 *
 * Only public keys are exported. Private keys are never extracted.
 */

/** Serialises a public CryptoKey to a JSON Web Key object. */
export async function exportPublicKeyAsJwk(key: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey('jwk', key)
}

/** Deserialises a JSON Web Key to a CryptoKey for the given algorithm. */
export async function importPublicKeyFromJwk(
  jwk: JsonWebKey,
  algorithm: 'ECDH' | 'ECDSA'
): Promise<CryptoKey> {
  const algorithmParams =
    algorithm === 'ECDH'
      ? { name: 'ECDH', namedCurve: 'P-256' }
      : { name: 'ECDSA', namedCurve: 'P-256' }

  // Public keys imported for verification/key-agreement don't need key usage flags
  const usages: KeyUsage[] = algorithm === 'ECDSA' ? ['verify'] : []

  return crypto.subtle.importKey('jwk', jwk, algorithmParams, true, usages)
}
