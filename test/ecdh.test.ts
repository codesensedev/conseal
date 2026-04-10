import { describe, it, expect } from 'vitest'
import { generateECDHKeyPair, sealMessage, unsealMessage } from '../src/ecdh'

describe('generateECDHKeyPair', () => {
  it('returns a P-256 key pair', async () => {
    const { publicKey, privateKey } = await generateECDHKeyPair()
    expect(publicKey.type).toBe('public')
    expect(privateKey.type).toBe('private')
    expect(publicKey.algorithm).toMatchObject({ name: 'ECDH', namedCurve: 'P-256' })
  })
})

describe('sealMessage / unsealMessage', () => {
  it('round-trips a message between two parties', async () => {
    const recipient = await generateECDHKeyPair()
    const plaintext = new TextEncoder().encode('secret message').buffer as ArrayBuffer
    const sealed = await sealMessage(recipient.publicKey, plaintext)
    const result = await unsealMessage(recipient.privateKey, sealed.ciphertext, sealed.iv, sealed.ephemeralPublicKey)
    expect(new TextDecoder().decode(result)).toBe('secret message')
  })

  it('includes an ephemeral public key as JWK', async () => {
    const { publicKey } = await generateECDHKeyPair()
    const plaintext = new TextEncoder().encode('test').buffer as ArrayBuffer
    const { ephemeralPublicKey } = await sealMessage(publicKey, plaintext)
    expect(ephemeralPublicKey.kty).toBe('EC')
    expect(ephemeralPublicKey.crv).toBe('P-256')
    // d (private component) must never appear in the ephemeral public key JWK
    expect(ephemeralPublicKey.d).toBeUndefined()
  })

  it('produces different ciphertext each call (fresh ephemeral key per message)', async () => {
    const { publicKey } = await generateECDHKeyPair()
    const plaintext = new TextEncoder().encode('same').buffer as ArrayBuffer
    const a = await sealMessage(publicKey, plaintext)
    const b = await sealMessage(publicKey, plaintext)
    expect(Array.from(a.iv)).not.toEqual(Array.from(b.iv))
  })

  it('throws when decrypting with wrong private key', async () => {
    const recipient = await generateECDHKeyPair()
    const attacker = await generateECDHKeyPair()
    const plaintext = new TextEncoder().encode('secret').buffer as ArrayBuffer
    const sealed = await sealMessage(recipient.publicKey, plaintext)
    await expect(
      unsealMessage(attacker.privateKey, sealed.ciphertext, sealed.iv, sealed.ephemeralPublicKey)
    ).rejects.toThrow()
  })

  it('handles empty plaintext', async () => {
    const recipient = await generateECDHKeyPair()
    const plaintext = new ArrayBuffer(0)
    const sealed = await sealMessage(recipient.publicKey, plaintext)
    const result = await unsealMessage(recipient.privateKey, sealed.ciphertext, sealed.iv, sealed.ephemeralPublicKey)
    expect(result.byteLength).toBe(0)
  })

  it('throws when recipient public key uses a mismatched curve (P-384 instead of P-256)', async () => {
    const p384KeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      ['deriveKey']
    )
    const plaintext = new TextEncoder().encode('test').buffer as ArrayBuffer
    await expect(sealMessage(p384KeyPair.publicKey, plaintext)).rejects.toThrow()
  })
})
