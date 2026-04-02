import { describe, it, expect } from 'vitest'
import { seal, unseal } from '../src/aes'

/** Generates a fresh AES-256-GCM CryptoKey for testing. */
async function makeKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

describe('seal / unseal', () => {
  it('round-trips plaintext', async () => {
    const key = await makeKey()
    const plaintext = new TextEncoder().encode('hello conseal').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(key, plaintext)
    const result = await unseal(key, ciphertext, iv)
    expect(new TextDecoder().decode(result)).toBe('hello conseal')
  })

  it('produces different ciphertext each call due to random IV', async () => {
    const key = await makeKey()
    const plaintext = new TextEncoder().encode('same input').buffer as ArrayBuffer
    const a = await seal(key, plaintext)
    const b = await seal(key, plaintext)
    expect(Array.from(a.iv)).not.toEqual(Array.from(b.iv))
  })

  it('throws on tampered ciphertext', async () => {
    const key = await makeKey()
    const plaintext = new TextEncoder().encode('hello').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(key, plaintext)
    const tampered = ciphertext.slice(0)
    new Uint8Array(tampered)[0] ^= 0xff
    await expect(unseal(key, tampered, iv)).rejects.toThrow()
  })

  it('throws on wrong key', async () => {
    const key1 = await makeKey()
    const key2 = await makeKey()
    const plaintext = new TextEncoder().encode('hello').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(key1, plaintext)
    await expect(unseal(key2, ciphertext, iv)).rejects.toThrow()
  })

  it('handles empty plaintext', async () => {
    const key = await makeKey()
    const plaintext = new ArrayBuffer(0)
    const { ciphertext, iv } = await seal(key, plaintext)
    const result = await unseal(key, ciphertext, iv)
    expect(result.byteLength).toBe(0)
  })

  it('throws on tampered IV', async () => {
    const key = await makeKey()
    const plaintext = new TextEncoder().encode('hello').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(key, plaintext)
    const tamperedIv = new Uint8Array(iv)
    tamperedIv[0] ^= 0xff
    await expect(unseal(key, ciphertext, tamperedIv)).rejects.toThrow()
  })

  it('throws when IV is wrong length', async () => {
    const key = await makeKey()
    const plaintext = new TextEncoder().encode('hello').buffer as ArrayBuffer
    const { ciphertext } = await seal(key, plaintext)
    const wrongIv = new Uint8Array(8) // 8 bytes instead of 12
    await expect(unseal(key, ciphertext, wrongIv)).rejects.toThrow()
  })
})
