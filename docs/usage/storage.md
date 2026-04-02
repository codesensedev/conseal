# storage.save / storage.load / storage.remove

IndexedDB persistence for CryptoKey objects. Imported as a separate entry point so applications that don't use IndexedDB don't pull it in.

## Signatures

```ts
save(name: string, key: CryptoKey): Promise<void>
load(name: string): Promise<CryptoKey | null>
remove(name: string): Promise<void>
```

## Example

```ts
import * as storage from 'conseal/storage'

// Store a key after generation
await storage.save('my-ecdh-private', keyPair.privateKey)

// Load it on next page load
const key = await storage.load('my-ecdh-private')
if (!key) {
  // Key not found — prompt user to set up device again
}

// Remove on sign-out
await storage.remove('my-ecdh-private')
```

## Notes

- Separate entry point: `import * as storage from 'conseal/storage'` — not included in the main `conseal` bundle.
- Uses IndexedDB database `conseal-keys`, object store `keys`.
- `load()` returns `null` if the name does not exist — always check the return value.
- `remove()` is a no-op if the name does not exist.
- Non-extractable keys cannot have their bytes read, but same-origin JavaScript can load and use them. XSS prevention is the application's responsibility.
