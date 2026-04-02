// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * ECDH P-256 asymmetric encryption for account-to-account message delivery.
 *
 * sealMessage() uses ephemeral ECDH: a fresh key pair is generated per message,
 * a shared AES-256-GCM key is derived via ECDH key agreement between the ephemeral
 * private key and the recipient's public key, and the plaintext is encrypted.
 * The ephemeral public key is returned alongside the ciphertext — the recipient
 * uses it to derive the same shared key and decrypt.
 *
 * The ephemeral private key is never stored or returned; it exists only in memory
 * for the duration of the sealMessage() call.
 *
 * unsealMessage() imports the ephemeral public key, derives the shared key using
 * the recipient's private key and the ephemeral public key, and decrypts.
 */

import { exportPublicKeyAsJwk, importPublicKeyFromJwk } from './jwk'

/** Generates a long-term ECDH P-256 key pair for an account identity. */
export async function generateECDHKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, // extractable: true — public key must be exportable as JWK for the registry
    ['deriveKey']
  )
}

async function deriveSharedKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

/** Encrypts plaintext for a recipient. Only the recipient's private key can decrypt. */
export async function sealMessage(
  recipientPublicKey: CryptoKey,
  plaintext: ArrayBuffer
): Promise<{ ciphertext: ArrayBuffer; iv: Uint8Array; ephemeralPublicKey: JsonWebKey }> {
  // Fresh ephemeral key pair per message — private key never leaves this function
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, // extractable: true — public key must be exported as JWK to send to recipient
    ['deriveKey']
  )
  const sharedKey = await deriveSharedKey(ephemeral.privateKey, recipientPublicKey)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 }, sharedKey, plaintext)
  const ephemeralPublicKey = await exportPublicKeyAsJwk(ephemeral.publicKey)
  return { ciphertext, iv, ephemeralPublicKey }
}

/** Decrypts a message sealed with the recipient's public key. */
export async function unsealMessage(
  recipientPrivateKey: CryptoKey,
  ciphertext: ArrayBuffer,
  iv: Uint8Array,
  ephemeralPublicKey: JsonWebKey
): Promise<ArrayBuffer> {
  const ephemeralKey = await importPublicKeyFromJwk(ephemeralPublicKey, 'ECDH')
  const sharedKey = await deriveSharedKey(recipientPrivateKey, ephemeralKey)
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 }, sharedKey, ciphertext)
}
