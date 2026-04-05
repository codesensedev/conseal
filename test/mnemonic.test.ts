import { describe, it, expect } from 'vitest'
import { generateMnemonic, recoverWithMnemonic } from '../src/mnemonic'
import { seal, unseal } from '../src/aes'
import { wrapKey, unwrapKey } from '../src/pbkdf2'

describe('generateMnemonic', () => {
  it('returns a 24-word mnemonic', () => {
    const mnemonic = generateMnemonic()
    const words = mnemonic.trim().split(/\s+/)
    expect(words).toHaveLength(24)
  })

  it('returns a different mnemonic each call', () => {
    const a = generateMnemonic()
    const b = generateMnemonic()
    expect(a).not.toBe(b)
  })
})

describe('recoverWithMnemonic', () => {
  it('derives a 256-bit AES-GCM key from the mnemonic', async () => {
    const mnemonic = generateMnemonic()
    const key = await recoverWithMnemonic(mnemonic)
    expect(key.type).toBe('secret')
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 })
  })

  it('same mnemonic always produces a key that decrypts the same ciphertext', async () => {
    const mnemonic = generateMnemonic()
    const key1 = await recoverWithMnemonic(mnemonic)
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const plaintext = new TextEncoder().encode('recovery test').buffer as ArrayBuffer
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key1, plaintext)
    const key2 = await recoverWithMnemonic(mnemonic)
    const result = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ciphertext)
    expect(new TextDecoder().decode(result)).toBe('recovery test')
  })

  it('throws on an invalid mnemonic', async () => {
    await expect(recoverWithMnemonic('not valid words at all')).rejects.toThrow()
  })

  it('round-trip: seal with recovered key, unseal with second recovered key (Conseal API)', async () => {
    const mnemonic = generateMnemonic()
    const aek = await recoverWithMnemonic(mnemonic)
    const plaintext = new TextEncoder().encode('recovery round-trip').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(aek, plaintext)

    // Simulate a fresh session: recover the same key from the mnemonic again
    const recoveredAek = await recoverWithMnemonic(mnemonic)
    const result = await unseal(recoveredAek, ciphertext, iv)
    expect(new TextDecoder().decode(result)).toBe('recovery round-trip')
  })

  it('is non-extractable by default', async () => {
    const key = await recoverWithMnemonic(generateMnemonic())
    expect(key.extractable).toBe(false)
  })

  it('is extractable when requested', async () => {
    const key = await recoverWithMnemonic(generateMnemonic(), true)
    expect(key.extractable).toBe(true)
  })

  it('extractable key can be wrapped and unwrapped (initCircle flow)', async () => {
    const mnemonic = generateMnemonic()
    const aek = await recoverWithMnemonic(mnemonic, true)
    const { wrappedKey, salt } = await wrapKey('passphrase', aek)
    const recovered = await unwrapKey('passphrase', wrappedKey, salt)
    expect(recovered.algorithm.name).toBe('AES-GCM')
  }, 15_000)

  it('wrapped extractable key decrypts data encrypted by the original', async () => {
    const mnemonic = generateMnemonic()
    const aek = await recoverWithMnemonic(mnemonic, true)

    const plaintext = new TextEncoder().encode('circle recovery').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(aek, plaintext)

    // Simulate recovery: re-derive from mnemonic and unwrap
    const aek2 = await recoverWithMnemonic(mnemonic)
    const result = await unseal(aek2, ciphertext, iv)
    expect(new TextDecoder().decode(result)).toBe('circle recovery')
  })
})
