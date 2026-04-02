/**
 * BIP-39 mnemonic generation and AEK recovery.
 *
 * generateMnemonic() produces a 24-word BIP-39 phrase (256 bits of entropy).
 * The user must store this phrase securely — it is the last-resort recovery path
 * when both the passphrase and the wrapped key are lost.
 *
 * recoverWithMnemonic() derives a deterministic AES-256-GCM key from the mnemonic's
 * entropy bytes. The same mnemonic always produces the same key — this is what makes
 * recovery possible.
 *
 * Dependency: @scure/bip39 (browser-compatible, audited)
 */

import { generateMnemonic as bip39Generate, mnemonicToEntropy, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'

/** Generates a fresh 24-word BIP-39 mnemonic (256 bits of entropy). */
export function generateMnemonic(): string {
  return bip39Generate(wordlist, 256)
}

/**
 * Derives a deterministic AES-256-GCM CryptoKey from a BIP-39 mnemonic.
 * Throws if the mnemonic is invalid or not in the BIP-39 word list.
 */
export async function recoverWithMnemonic(mnemonic: string): Promise<CryptoKey> {
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new Error('Invalid mnemonic: phrase does not pass BIP-39 checksum validation')
  }
  // mnemonicToEntropy returns the raw entropy bytes — 32 bytes for a 24-word phrase
  const entropy = mnemonicToEntropy(mnemonic, wordlist)
  return crypto.subtle.importKey(
    'raw',
    entropy as BufferSource,
    { name: 'AES-GCM', length: 256 },
    false, // extractable: false — key is for use only, never exported
    ['encrypt', 'decrypt']
  )
}
