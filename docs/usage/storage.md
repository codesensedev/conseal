# save / load / remove

IndexedDB persistence for CryptoKey objects.

## Signatures

```ts
save(name: string, key: CryptoKey): Promise<void>
load(name: string): Promise<CryptoKey | null>
remove(name: string): Promise<void>
```

## Example

```ts
import { save, load, remove } from 'conseal'
// or: import * as storage from 'conseal/storage'

// Store a key after generation
await save('my-ecdh-private', keyPair.privateKey)

// Load it on next page load
const key = await load('my-ecdh-private')
if (!key) {
  // Key not found — prompt user to set up device again
}

// Remove on sign-out
await remove('my-ecdh-private')
```

## Notes

- Also available as separate entry point: `import * as storage from 'conseal/storage'`
- Uses IndexedDB database `conseal-keys`, object store `keys`.
- `load()` returns `null` if the name does not exist — always check the return value.
- `remove()` is a no-op if the name does not exist.
- Non-extractable keys cannot have their bytes read, but same-origin JavaScript can load and use them. XSS prevention is the application's responsibility.
