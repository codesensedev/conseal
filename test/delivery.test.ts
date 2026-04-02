import { describe, it, expect } from 'vitest'
import { sealDelivery, unsealDelivery } from '../src/delivery'

describe('sealDelivery / unsealDelivery', () => {
  it('round-trips plaintext with the correct passcode', async () => {
    const plaintext = new TextEncoder().encode('confidential document').buffer as ArrayBuffer
    const sealed = await sealDelivery(plaintext, 'correct-passcode')
    const result = await unsealDelivery(
      sealed.ciphertext, sealed.iv, sealed.wrappedKey, sealed.salt, 'correct-passcode'
    )
    expect(new TextDecoder().decode(result)).toBe('confidential document')
  }, 15_000)

  it('throws when wrong passcode is used', async () => {
    const plaintext = new TextEncoder().encode('secret').buffer as ArrayBuffer
    const sealed = await sealDelivery(plaintext, 'correct')
    await expect(
      unsealDelivery(sealed.ciphertext, sealed.iv, sealed.wrappedKey, sealed.salt, 'wrong')
    ).rejects.toThrow()
  }, 15_000)

  it('produces different ciphertext each call (random DEK)', async () => {
    const plaintext = new TextEncoder().encode('same').buffer as ArrayBuffer
    const a = await sealDelivery(plaintext, 'pass')
    const b = await sealDelivery(plaintext, 'pass')
    expect(Array.from(a.iv)).not.toEqual(Array.from(b.iv))
  }, 20_000)

  it('returns all fields needed for server storage', async () => {
    const plaintext = new TextEncoder().encode('test').buffer as ArrayBuffer
    const { ciphertext, iv, wrappedKey, salt } = await sealDelivery(plaintext, 'pass')
    expect(ciphertext).toBeInstanceOf(ArrayBuffer)
    expect(iv).toBeInstanceOf(Uint8Array)
    expect(wrappedKey).toBeInstanceOf(ArrayBuffer)
    expect(salt).toBeInstanceOf(Uint8Array)
  }, 10_000)
})
