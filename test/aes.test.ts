import { describe, it, expect } from 'vitest'
import { seal, unseal, generateAesKey, importAesKey } from '../src/aes'

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

  it('always returns a 12-byte IV', async () => {
    const key = await makeKey()
    const plaintext = new TextEncoder().encode('hello').buffer as ArrayBuffer
    const { iv } = await seal(key, plaintext)
    expect(iv.byteLength).toBe(12)
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

  it('round-trips plaintext larger than 1 MB', async () => {
    const key = await makeKey()
    const plaintext = new Uint8Array(1_200_000).fill(0x42).buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(key, plaintext)
    const result = await unseal(key, ciphertext, iv)
    expect(result.byteLength).toBe(plaintext.byteLength)
    expect(new Uint8Array(result)[0]).toBe(0x42)
    expect(new Uint8Array(result)[1_199_999]).toBe(0x42)
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

  it('round-trips plaintext with additionalData', async () => {
    const key = await makeKey()
    const plaintext = new TextEncoder().encode('hello conseal').buffer as ArrayBuffer
    const aad = new TextEncoder().encode('record-id-42')
    const { ciphertext, iv } = await seal(key, plaintext, aad)
    const result = await unseal(key, ciphertext, iv, aad)
    expect(new TextDecoder().decode(result)).toBe('hello conseal')
  })

  it('throws when additionalData does not match on unseal', async () => {
    const key = await makeKey()
    const plaintext = new TextEncoder().encode('hello').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(key, plaintext, new TextEncoder().encode('record-a'))
    await expect(unseal(key, ciphertext, iv, new TextEncoder().encode('record-b'))).rejects.toThrow()
  })

  it('throws when additionalData is omitted on unseal but was used on seal', async () => {
    const key = await makeKey()
    const plaintext = new TextEncoder().encode('hello').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(key, plaintext, new TextEncoder().encode('record-id'))
    await expect(unseal(key, ciphertext, iv)).rejects.toThrow()
  })

  it('accepts ArrayBuffer as additionalData', async () => {
    const key = await makeKey()
    const plaintext = new TextEncoder().encode('hello').buffer as ArrayBuffer
    const aad = new TextEncoder().encode('ctx').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(key, plaintext, aad)
    const result = await unseal(key, ciphertext, iv, aad)
    expect(new TextDecoder().decode(result)).toBe('hello')
  })
})

describe('generateAesKey', () => {
  it('returns a CryptoKey with correct algorithm', async () => {
    const key = await generateAesKey()
    expect(key.algorithm.name).toBe('AES-GCM')
    expect((key.algorithm as AesKeyAlgorithm).length).toBe(256)
  })

  it('is non-extractable by default', async () => {
    const key = await generateAesKey()
    expect(key.extractable).toBe(false)
  })

  it('is extractable when requested', async () => {
    const key = await generateAesKey(true)
    expect(key.extractable).toBe(true)
  })

  it('can be used to seal and unseal', async () => {
    const key = await generateAesKey()
    const plaintext = new TextEncoder().encode('test').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(key, plaintext)
    const result = await unseal(key, ciphertext, iv)
    expect(new TextDecoder().decode(result)).toBe('test')
  })
})

describe('importAesKey', () => {
  it('imports 32 raw bytes as an AES-GCM key', async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32))
    const key = await importAesKey(raw)
    expect(key.algorithm.name).toBe('AES-GCM')
    expect((key.algorithm as AesKeyAlgorithm).length).toBe(256)
  })

  it('is non-extractable by default', async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32))
    const key = await importAesKey(raw)
    expect(key.extractable).toBe(false)
  })

  it('is extractable when requested', async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32))
    const key = await importAesKey(raw, true)
    expect(key.extractable).toBe(true)
  })

  it('produces the same key from the same raw bytes', async () => {
    const raw = new Uint8Array(32).fill(0xab)
    const key1 = await importAesKey(raw)
    const key2 = await importAesKey(raw)
    const plaintext = new TextEncoder().encode('deterministic').buffer as ArrayBuffer
    const { ciphertext, iv } = await seal(key1, plaintext)
    const result = await unseal(key2, ciphertext, iv)
    expect(new TextDecoder().decode(result)).toBe('deterministic')
  })

  it('accepts ArrayBuffer input', async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer
    const key = await importAesKey(raw)
    expect(key.algorithm.name).toBe('AES-GCM')
  })

  it('throws on wrong key length', async () => {
    await expect(importAesKey(new Uint8Array(16))).rejects.toThrow('32 bytes')
    await expect(importAesKey(new Uint8Array(0))).rejects.toThrow('32 bytes')
    await expect(importAesKey(new Uint8Array(64))).rejects.toThrow('32 bytes')
  })
})
