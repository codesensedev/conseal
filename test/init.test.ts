import { describe, it, expect, beforeEach } from 'vitest'
import { init, AEK_KEY_ID } from '../src/init'
import { wrapKey } from '../src/pbkdf2'
import { loadCryptoKey } from '../src/storage'
import { generateSecretKey } from '../src/secret-key'
import { generateAesKey, seal, unseal } from '../src/aes'

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
    const stored = await loadCryptoKey(AEK_KEY_ID)
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

  it('unwraps the AEK and saves it to IndexedDB when secret key is provided', async () => {
    const aek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )
    const sk = generateSecretKey()
    const { wrappedKey, salt } = await wrapKey('my-passphrase', aek, sk)
    await init(wrappedKey, salt, 'my-passphrase', sk)
    const stored = await loadCryptoKey(AEK_KEY_ID)
    expect(stored).not.toBeNull()
    expect(stored!.type).toBe('secret')
  }, 15_000)

  it('throws when secret key is wrong', async () => {
    const aek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )
    const sk = generateSecretKey()
    const { wrappedKey, salt } = await wrapKey('my-passphrase', aek, sk)
    const wrongSk = generateSecretKey()
    await expect(init(wrappedKey, salt, 'my-passphrase', wrongSk)).rejects.toThrow()
  }, 15_000)

  it('second call overwrites the first AEK', async () => {
    const aek1 = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )
    const aek2 = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )

    // Seal data with aek1
    const plaintext = new TextEncoder().encode('from aek1').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(aek1, plaintext)

    const { wrappedKey: wk1, salt: s1 } = await wrapKey('pass1', aek1)
    await init(wk1, s1, 'pass1')

    // Call init a second time with a different AEK
    const { wrappedKey: wk2, salt: s2 } = await wrapKey('pass2', aek2)
    await init(wk2, s2, 'pass2')

    // The stored key is now aek2 — decrypting aek1-ciphertext must fail
    const stored = await loadCryptoKey(AEK_KEY_ID)
    await expect(unseal(stored!, ciphertext, iv)).rejects.toThrow()
  }, 25_000)

  it('end-to-end with secret key: seal data, init on new device, unseal data', async () => {
    const secretKey = generateSecretKey()
    const aek = await generateAesKey(true)
    const plaintext = new TextEncoder().encode('protected by secret key').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(aek, plaintext)
    const { wrappedKey, salt } = await wrapKey('strong-passphrase', aek, secretKey)

    // Simulate new device: init with passphrase + secret key, then load and decrypt
    await init(wrappedKey, salt, 'strong-passphrase', secretKey)
    const loadedAek = await loadCryptoKey(AEK_KEY_ID)
    const result = await unseal(loadedAek!, ciphertext, iv)
    expect(new TextDecoder().decode(result)).toBe('protected by secret key')
  }, 20_000)
})
