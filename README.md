<p align="center">
  <img src="docs/assets/logo.svg" width="64" height="64" alt="Conseal logo">
</p>

<h1 align="center">Conseal</h1>

<p align="center">
  Browser-side zero-knowledge cryptography library.<br>
  All crypto runs in the browser via <a href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto">SubtleCrypto</a> — the server never sees plaintext or key material.
</p>

---

## Install

```bash
npm install conseal
```

## Quick start

```ts
import { seal, unseal, generateAesKey } from 'conseal'

// Generate a key and encrypt
const key = await generateAesKey()
const plaintext = await file.arrayBuffer()
const { ciphertext, iv } = await seal(key, plaintext)

// Decrypt
const result = await unseal(key, ciphertext, iv)
```

## API

### Symmetric encryption (AES-256-GCM)

| Function | Description |
|---|---|
| `seal(key, plaintext)` | Encrypts with a random 96-bit IV. Returns `{ ciphertext, iv }`. |
| `unseal(key, ciphertext, iv)` | Decrypts. Throws on tampered data. |
| `generateAesKey(extractable?)` | Generates a random AES-256 key. |
| `importAesKey(raw, extractable?)` | Imports raw key bytes as a CryptoKey. |

### Passphrase key wrapping (PBKDF2 + AES-KW)

| Function | Description |
|---|---|
| `wrapKey(passphrase, key)` | Wraps a CryptoKey with a passphrase. Returns `{ wrappedKey, salt }`. |
| `unwrapKey(passphrase, wrappedKey, salt)` | Unwraps. Throws on wrong passphrase. |
| `rekey(oldPass, newPass, wrappedKey, salt)` | Changes passphrase without re-encrypting data. |

### Asymmetric encryption (ECDH P-256)

| Function | Description |
|---|---|
| `sealMessage(recipientPublicKey, plaintext)` | Encrypts for a recipient using ephemeral ECDH. |
| `unsealMessage(privateKey, ciphertext, iv, ephemeralPublicKey)` | Decrypts with the recipient's private key. |
| `generateECDHKeyPair()` | Generates a P-256 ECDH key pair. |

### Digital signatures (ECDSA P-256)

| Function | Description |
|---|---|
| `sign(privateKey, data)` | Signs data with ECDSA-SHA256. |
| `verify(publicKey, signature, data)` | Verifies a signature. Returns `true` or `false`. |
| `generateECDSAKeyPair()` | Generates a P-256 ECDSA key pair. |

### Envelope encryption (passcode-protected)

| Function | Description |
|---|---|
| `sealEnvelope(plaintext, passcode)` | Encrypts for a recipient without a Conseal account. |
| `unsealEnvelope(envelope, passcode)` | Decrypts with the passcode. |
| `encodeEnvelope(envelope)` | Serialises a `SealedEnvelope` to JSON. |
| `decodeEnvelope(json)` | Deserialises JSON back to a `SealedEnvelope`. |

### Device initialisation

| Function | Description |
|---|---|
| `init(wrappedKey, salt, passphrase)` | Unwraps the AEK and stores it in IndexedDB. |
| `AEK_KEY_ID` | The IndexedDB key id for the AEK (`'aek'`). |

### Mnemonic recovery (BIP-39)

| Function | Description |
|---|---|
| `generateMnemonic()` | Generates a 24-word recovery phrase. |
| `recoverWithMnemonic(mnemonic)` | Derives the AEK from the mnemonic. |

### Key serialisation (JWK)

| Function | Description |
|---|---|
| `exportPublicKeyAsJwk(key)` | Exports a public CryptoKey to JWK. |
| `importPublicKeyFromJwk(jwk, algorithm)` | Imports a JWK as a CryptoKey (`'ECDH'` or `'ECDSA'`). |

### IndexedDB key storage

```ts
import { save, load, remove } from 'conseal/storage'
```

| Function | Description |
|---|---|
| `save(name, key)` | Persists a CryptoKey to IndexedDB. |
| `load(name)` | Loads a CryptoKey. Returns `null` if not found. |
| `remove(name)` | Deletes a CryptoKey. |

### Utilities

| Function | Description |
|---|---|
| `toBase64(buf)` / `fromBase64(b64)` | Standard base64 encoding/decoding. |
| `toBase64Url(buf)` / `fromBase64Url(b64)` | URL-safe base64 (no padding). |
| `digest(data)` | SHA-256 hash. |

## Design

- **Zero runtime secrets on the server.** All encryption and decryption happens in the browser. The server stores only wrapped keys and ciphertext.
- **SubtleCrypto everywhere.** No OpenSSL, no polyfills, no WASM. The only runtime dependency is [`@scure/bip39`](https://github.com/nicolo-ribaudo/noble-bip39) for mnemonic wordlists (bundled into the output).
- **Non-extractable keys.** Keys stored in IndexedDB have `extractable: false` — JavaScript cannot read the raw bytes, only use them for encrypt/decrypt.
- **PBKDF2 at 600,000 iterations.** Passphrase-derived keys use SHA-256 with a 128-bit random salt per wrap. Intentionally slow to resist offline brute-force.

## Requirements

- Browser with [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) support (all modern browsers)
- Node.js >= 18 (for testing / SSR with `globalThis.crypto`)

## Development

```bash
npm install
npm test           # run tests
npm run build      # build to dist/
```

## License

Dual-licensed under [AGPL-3.0](LICENSE) and a [commercial license](COMMERCIAL-LICENSE.md).
