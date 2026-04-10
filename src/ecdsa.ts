// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * ECDSA P-256 signing for sender verification.
 *
 * Provides cryptographic proof that a file or message came from the claimed sender.
 * The sender signs with their private key; any recipient who has the sender's public
 * key can verify the signature.
 *
 * sign()   produces a raw ECDSA signature over arbitrary data.
 * verify() checks a signature against data using the signer's public key.
 *          Returns true if valid, false if not — never throws on invalid signatures.
 *
 * Hash: SHA-256.
 */

/** Generates a long-term ECDSA P-256 key pair for an account identity. */
export async function generateECDSAKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // extractable: true — public key must be exportable as JWK for the registry
    ['sign', 'verify']
  )
}

/** Signs data with the sender's ECDSA private key. */
export async function sign(privateKey: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
  if (privateKey.algorithm.name !== 'ECDSA') {
    throw new TypeError(`sign: expected an ECDSA private key, got ${privateKey.algorithm.name}`)
  }
  return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data)
}

/** Verifies a signature against data using the sender's ECDSA public key. */
export async function verify(
  publicKey: CryptoKey,
  signature: ArrayBuffer,
  data: ArrayBuffer
): Promise<boolean> {
  if (publicKey.algorithm.name !== 'ECDSA') {
    throw new TypeError(`verify: expected an ECDSA public key, got ${publicKey.algorithm.name}`)
  }
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, data)
}
