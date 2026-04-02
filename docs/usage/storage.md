# saveKey / loadKey / deleteKey

IndexedDB persistence for CryptoKey objects.

## Signatures

```ts
saveKey(id: string, key: CryptoKey): Promise<void>
loadKey(id: string): Promise<CryptoKey | null>
deleteKey(id: string): Promise<void>
```

## Example

```ts
import { saveKey, loadKey, deleteKey } from 'conseal'

// Store a key after generation
await saveKey('my-ecdh-private', keyPair.privateKey)

// Load it on next page load
const key = await loadKey('my-ecdh-private')
if (!key) {
  // Key not found — prompt user to set up device again
}

// Remove on sign-out
await deleteKey('my-ecdh-private')
```

## Notes

- Uses IndexedDB database `conseal-keys`, object store `keys`.
- `loadKey()` returns `null` if the id does not exist — always check the return value.
- `deleteKey()` is a no-op if the id does not exist.
- Non-extractable keys cannot have their bytes read, but same-origin JavaScript can load and use them. XSS prevention is the application's responsibility.
