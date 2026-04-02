import { describe, it, expect, beforeEach } from 'vitest'
import { init, AEK_KEY_ID } from '../src/init'
import { wrapKey } from '../src/pbkdf2'
import { load } from '../src/storage'

beforeEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const req = indexedDB.deleteDatabase('conseal-keys')
    req.onsuccess = () => resolve()
    req.onerror = () => reject(req.error)
  })
})

describe('init', () => {
  it('unwraps the AEK and saves it to IndexedDB', async () => {
    // Simulate account setup: generate AEK and wrap it with a passphrase
    const aek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable: true required for wrapKey
      ['encrypt', 'decrypt']
    )
    const { wrappedKey, salt } = await wrapKey('my-passphrase', aek)

    // Run init — simulates new device login
    await init(wrappedKey, salt, 'my-passphrase')

    // AEK should now be in IndexedDB
    const stored = await load(AEK_KEY_ID)
    expect(stored).not.toBeNull()
    expect(stored!.type).toBe('secret')
  }, 15_000)

  it('throws when passphrase is wrong', async () => {
    const aek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )
    const { wrappedKey, salt } = await wrapKey('correct', aek)
    await expect(init(wrappedKey, salt, 'wrong')).rejects.toThrow()
  }, 15_000)
})
