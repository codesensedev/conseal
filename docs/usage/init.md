# init / AEK_KEY_ID

New device setup. Unwraps the AEK with the user's passphrase and stores it in IndexedDB.

## Signatures

```ts
init(wrappedKey: ArrayBuffer, salt: Uint8Array, passphrase: string): Promise<void>
AEK_KEY_ID: string  // 'aek'
```

## Example

```ts
import { init, AEK_KEY_ID, load, seal } from 'conseal'

// On new device after OAuth login:
// 1. Fetch wrappedKey + salt from server (or accept user key file upload)
const resp = await fetch('/account/wrapped-key').then(r => r.json())
const wrappedKey = Uint8Array.from(atob(resp.wrappedKey), c => c.charCodeAt(0)).buffer
const salt = Uint8Array.from(atob(resp.salt), c => c.charCodeAt(0))

// 2. Prompt user for their passphrase
await init(wrappedKey, salt, userPassphrase)

// 3. AEK is now in IndexedDB — load and use it
const aek = await load(AEK_KEY_ID)
const { ciphertext, iv } = await seal(aek!, plaintext)
```

## Notes

- Throws if the passphrase is wrong.
- After `init()`, the AEK is stored under `AEK_KEY_ID` (`'aek'`).
