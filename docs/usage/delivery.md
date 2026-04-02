# sealDelivery / unsealDelivery

Anonymous one-time delivery encryption for recipients without a Conseal account.

## Signatures

```ts
sealDelivery(plaintext: ArrayBuffer, passcode: string): Promise<{ ciphertext: ArrayBuffer, iv: Uint8Array, wrappedKey: ArrayBuffer, salt: Uint8Array }>
unsealDelivery(ciphertext: ArrayBuffer, iv: Uint8Array, wrappedKey: ArrayBuffer, salt: Uint8Array, passcode: string): Promise<ArrayBuffer>
```

## Example

```ts
import { sealDelivery, unsealDelivery } from 'conseal'

// Sender: seal the file and upload the result to the server
const plaintext = await file.arrayBuffer()
const { ciphertext, iv, wrappedKey, salt } = await sealDelivery(plaintext, 'tiger-moon-7')
// POST { ciphertext, iv, wrappedKey, salt } → server returns a link id
// Sender shares:
//   Link  → via email/message (comes from sender's own address)
//   Passcode 'tiger-moon-7' → via separate channel (SMS, phone call)

// Recipient: open the link, enter the passcode, decrypt in browser
const { ciphertext, iv, wrappedKey, salt } = await fetch(`/d/${linkId}`).then(r => r.json())
const result = await unsealDelivery(ciphertext, iv, wrappedKey, salt, 'tiger-moon-7')
const blob = new Blob([result])
```

## Notes

- The server stores `{ ciphertext, iv, wrappedKey, salt }` — useless without the passcode.
- The passcode must travel via a different channel than the link (two-channel delivery).
- `sealDelivery()` takes ~500ms due to PBKDF2 — show a loading indicator.
- Throws if the passcode is wrong.
