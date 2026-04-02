/**
 * Conseal — browser-side zero-knowledge cryptography library.
 *
 * Import everything from 'conseal':
 *
 *   import { seal, unseal, wrapKey, init, sealMessage, ... } from 'conseal'
 *
 * See docs/usage/ for per-function examples.
 */

// AES-256-GCM symmetric encryption
export { seal, unseal, generateAesKey, importAesKey } from './aes'

// PBKDF2 passphrase-based key wrapping
export { wrapKey, unwrapKey, rekey } from './pbkdf2'

// ECDH P-256 message encryption
export { generateECDHKeyPair, sealMessage, unsealMessage } from './ecdh'

// ECDSA P-256 signing
export { generateECDSAKeyPair, sign, verify } from './ecdsa'

// JWK public key serialisation
export { exportPublicKeyAsJwk, importPublicKeyFromJwk } from './jwk'

// IndexedDB key storage
export { saveKey, loadKey, deleteKey } from './storage'

// New device initialisation
export { init, AEK_KEY_ID } from './init'

// BIP-39 mnemonic recovery
export { generateMnemonic, recoverWithMnemonic } from './mnemonic'

// Anonymous one-time delivery
export { sealDelivery, unsealDelivery, encodePayload, decodePayload } from './delivery'
export type { SealedPayload } from './delivery'

// Base64 encoding / decoding
export { toBase64, fromBase64, toBase64Url, fromBase64Url } from './base64'

// SHA-256 digest
export { digest } from './digest'
