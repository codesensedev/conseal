import { describe, it, expect } from 'vitest'
import { sealEnvelope, unsealEnvelope, encodeEnvelope, decodeEnvelope, type SealedEnvelope } from '../src/envelope'

describe('sealEnvelope / unsealEnvelope', () => {
  it('round-trips plaintext with the correct passcode', async () => {
    const plaintext = new TextEncoder().encode('confidential document').buffer as ArrayBuffer
    const sealed = await sealEnvelope(plaintext, 'correct-passcode')
    const result = await unsealEnvelope(sealed, 'correct-passcode')
    expect(new TextDecoder().decode(result)).toBe('confidential document')
  }, 15_000)

  it('throws when wrong passcode is used', async () => {
    const plaintext = new TextEncoder().encode('secret').buffer as ArrayBuffer
    const sealed = await sealEnvelope(plaintext, 'correct')
    await expect(
      unsealEnvelope(sealed, 'wrong')
    ).rejects.toThrow()
  }, 15_000)

  it('produces different ciphertext each call (random DEK)', async () => {
    const plaintext = new TextEncoder().encode('same').buffer as ArrayBuffer
    const a = await sealEnvelope(plaintext, 'pass')
    const b = await sealEnvelope(plaintext, 'pass')
    expect(Array.from(a.iv)).not.toEqual(Array.from(b.iv))
  }, 20_000)

  it('returns all fields needed for server storage', async () => {
    const plaintext = new TextEncoder().encode('test').buffer as ArrayBuffer
    const { ciphertext, iv, wrappedKey, salt } = await sealEnvelope(plaintext, 'pass')
    expect(ciphertext).toBeInstanceOf(ArrayBuffer)
    expect(iv).toBeInstanceOf(Uint8Array)
    expect(wrappedKey).toBeInstanceOf(ArrayBuffer)
    expect(salt).toBeInstanceOf(Uint8Array)
  }, 10_000)

  it('includes version: 1', async () => {
    const plaintext = new TextEncoder().encode('test').buffer as ArrayBuffer
    const envelope = await sealEnvelope(plaintext, 'pass')
    expect(envelope.version).toBe(1)
  }, 10_000)
})

describe('encodeEnvelope / decodeEnvelope', () => {
  it('round-trips a sealed envelope', async () => {
    const plaintext = new TextEncoder().encode('round trip').buffer as ArrayBuffer
    const sealed = await sealEnvelope(plaintext, 'pass')
    const json = encodeEnvelope(sealed)
    const decoded = decodeEnvelope(json)
    expect(decoded.ciphertext.byteLength).toBe(sealed.ciphertext.byteLength)
    expect(Array.from(decoded.iv)).toEqual(Array.from(sealed.iv))
    expect(Array.from(new Uint8Array(decoded.wrappedKey))).toEqual(Array.from(new Uint8Array(sealed.wrappedKey)))
    expect(Array.from(decoded.salt)).toEqual(Array.from(sealed.salt))
  }, 15_000)

  it('encoded envelope is valid JSON with expected keys', async () => {
    const plaintext = new TextEncoder().encode('test').buffer as ArrayBuffer
    const sealed = await sealEnvelope(plaintext, 'pass')
    const json = encodeEnvelope(sealed)
    const parsed = JSON.parse(json)
    expect(parsed).toHaveProperty('version', 1)
    expect(parsed).toHaveProperty('ciphertext')
    expect(parsed).toHaveProperty('iv')
    expect(parsed).toHaveProperty('wrappedKey')
    expect(parsed).toHaveProperty('salt')
  }, 15_000)

  it('encoded envelope is compact JSON (no extra whitespace)', async () => {
    const plaintext = new TextEncoder().encode('test').buffer as ArrayBuffer
    const sealed = await sealEnvelope(plaintext, 'pass')
    const json = encodeEnvelope(sealed)
    expect(json).not.toMatch(/\n/)
    expect(json).not.toMatch(/  /)
  }, 10_000)

  it('decoded envelope can be used to unseal', async () => {
    const plaintext = new TextEncoder().encode('end to end').buffer as ArrayBuffer
    const sealed = await sealEnvelope(plaintext, 'mypasscode')
    const json = encodeEnvelope(sealed)
    const decoded = decodeEnvelope(json)
    const result = await unsealEnvelope(decoded, 'mypasscode')
    expect(new TextDecoder().decode(result)).toBe('end to end')
  }, 20_000)

  it('decodeEnvelope throws on invalid JSON', () => {
    expect(() => decodeEnvelope('not json')).toThrow(SyntaxError)
  })

  it('decodeEnvelope throws on missing or wrong version', () => {
    const base = { ciphertext: 'YQ==', iv: 'YQ==', wrappedKey: 'YQ==', salt: 'YQ==' }
    expect(() => decodeEnvelope(JSON.stringify(base))).toThrow(/version/)
    expect(() => decodeEnvelope(JSON.stringify({ ...base, version: 2 }))).toThrow(/version/)
    expect(() => decodeEnvelope(JSON.stringify({ ...base, version: 'one' }))).toThrow(/version/)
  })

  it('decodeEnvelope throws on missing binary fields', () => {
    expect(() => decodeEnvelope(JSON.stringify({ version: 1 }))).toThrow(TypeError)
    expect(() => decodeEnvelope(JSON.stringify({ version: 1, ciphertext: 'YQ==' }))).toThrow(TypeError)
    expect(() => decodeEnvelope(JSON.stringify({ version: 1, ciphertext: 'YQ==', iv: 'YQ==', wrappedKey: 'YQ==' }))).toThrow(TypeError)
  })

  it('decodeEnvelope throws on non-string binary fields', () => {
    expect(() => decodeEnvelope(JSON.stringify({ version: 1, ciphertext: 123, iv: 'YQ==', wrappedKey: 'YQ==', salt: 'YQ==' }))).toThrow(TypeError)
    expect(() => decodeEnvelope(JSON.stringify({ version: 1, ciphertext: 'YQ==', iv: null, wrappedKey: 'YQ==', salt: 'YQ==' }))).toThrow(TypeError)
  })

  it('decodeEnvelope throws on invalid base64 content', () => {
    expect(() => decodeEnvelope(JSON.stringify({ version: 1, ciphertext: '!!!', iv: 'YQ==', wrappedKey: 'YQ==', salt: 'YQ==' }))).toThrow(/not valid base64/)
    expect(() => decodeEnvelope(JSON.stringify({ version: 1, ciphertext: 'YQ==', iv: 'not base64!!', wrappedKey: 'YQ==', salt: 'YQ==' }))).toThrow(/not valid base64/)
  })
})
