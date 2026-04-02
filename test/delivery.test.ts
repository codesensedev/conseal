import { describe, it, expect } from 'vitest'
import { sealDelivery, unsealDelivery, encodePayload, decodePayload } from '../src/delivery'

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

describe('encodePayload / decodePayload', () => {
  it('round-trips a sealed payload', async () => {
    const plaintext = new TextEncoder().encode('round trip').buffer as ArrayBuffer
    const sealed = await sealDelivery(plaintext, 'pass')
    const json = encodePayload(sealed)
    const decoded = decodePayload(json)
    expect(decoded.ciphertext.byteLength).toBe(sealed.ciphertext.byteLength)
    expect(Array.from(decoded.iv)).toEqual(Array.from(sealed.iv))
    expect(Array.from(new Uint8Array(decoded.wrappedKey))).toEqual(Array.from(new Uint8Array(sealed.wrappedKey)))
    expect(Array.from(decoded.salt)).toEqual(Array.from(sealed.salt))
  }, 15_000)

  it('encoded payload is valid JSON with expected keys', async () => {
    const plaintext = new TextEncoder().encode('test').buffer as ArrayBuffer
    const sealed = await sealDelivery(plaintext, 'pass')
    const json = encodePayload(sealed)
    const parsed = JSON.parse(json)
    expect(parsed).toHaveProperty('ciphertext')
    expect(parsed).toHaveProperty('iv')
    expect(parsed).toHaveProperty('wrappedKey')
    expect(parsed).toHaveProperty('salt')
  }, 15_000)

  it('decoded payload can be used to unseal', async () => {
    const plaintext = new TextEncoder().encode('end to end').buffer as ArrayBuffer
    const sealed = await sealDelivery(plaintext, 'mypasscode')
    const json = encodePayload(sealed)
    const { ciphertext, iv, wrappedKey, salt } = decodePayload(json)
    const result = await unsealDelivery(ciphertext, iv, wrappedKey, salt, 'mypasscode')
    expect(new TextDecoder().decode(result)).toBe('end to end')
  }, 20_000)

  it('decodePayload throws on invalid JSON', () => {
    expect(() => decodePayload('not json')).toThrow(SyntaxError)
  })
})
