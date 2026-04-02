# wrapKey / unwrapKey / rekey

PBKDF2-SHA256 key derivation and AES-KW key wrapping. Use this to protect an AEK with a user passphrase.

## Signatures

```ts
wrapKey(passphrase: string, key: CryptoKey): Promise<{ wrappedKey: ArrayBuffer, salt: Uint8Array }>
unwrapKey(passphrase: string, wrappedKey: ArrayBuffer, salt: Uint8Array): Promise<CryptoKey>
rekey(oldPassphrase: string, newPassphrase: string, wrappedKey: ArrayBuffer, salt: Uint8Array): Promise<{ wrappedKey: ArrayBuffer, salt: Uint8Array }>
```

## Example: account setup

```ts
import { wrapKey, unwrapKey, rekey } from 'conseal'

// Account setup: generate AEK, wrap with passphrase, store wrapped key + salt on server
const aek = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
)
const { wrappedKey, salt } = await wrapKey('my-strong-passphrase', aek)
// POST { wrappedKey: btoa(...), salt: btoa(...) } to server

// New device: fetch wrappedKey + salt, unwrap with passphrase
const recovered = await unwrapKey('my-strong-passphrase', wrappedKey, salt)

// Passphrase change — no files need re-encryption
const { wrappedKey: newWrapped, salt: newSalt } = await rekey('old-pass', 'new-pass', wrappedKey, salt)
```

## Notes

- `wrapKey()` requires the key to have `extractable: true`. Throws if `key.extractable` is false.
- `unwrapKey()` always returns `extractable: false` — safe for IndexedDB storage.
- PBKDF2 at 600,000 iterations takes ~200–500ms — this is intentional offline brute-force protection.
- The `salt` is not secret. Store it alongside `wrappedKey`.
