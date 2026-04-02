// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

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

  // ECDSA public keys need 'verify'; ECDH public keys need no usages (deriveBits is on the private key)
  const usages: KeyUsage[] = algorithm === 'ECDSA' ? ['verify'] : []

  return crypto.subtle.importKey('jwk', jwk, algorithmParams, true, usages)
}
