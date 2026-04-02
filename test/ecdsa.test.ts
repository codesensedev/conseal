import { describe, it, expect } from 'vitest'
import { generateECDSAKeyPair, sign, verify } from '../src/ecdsa'

describe('generateECDSAKeyPair', () => {
  it('returns a P-256 key pair', async () => {
    const { publicKey, privateKey } = await generateECDSAKeyPair()
    expect(publicKey.type).toBe('public')
    expect(privateKey.type).toBe('private')
    expect(publicKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' })
  })
})

describe('sign / verify', () => {
  it('verifies a valid signature', async () => {
    const { publicKey, privateKey } = await generateECDSAKeyPair()
    const data = new TextEncoder().encode('document content').buffer as ArrayBuffer
    const signature = await sign(privateKey, data)
    const valid = await verify(publicKey, signature, data)
    expect(valid).toBe(true)
  })

  it('rejects a tampered payload', async () => {
    const { publicKey, privateKey } = await generateECDSAKeyPair()
    const data = new TextEncoder().encode('original').buffer as ArrayBuffer
    const signature = await sign(privateKey, data)
    const tampered = new TextEncoder().encode('modified').buffer as ArrayBuffer
    const valid = await verify(publicKey, signature, tampered)
    expect(valid).toBe(false)
  })

  it('rejects a signature from a different key', async () => {
    const signer = await generateECDSAKeyPair()
    const verifier = await generateECDSAKeyPair()
    const data = new TextEncoder().encode('data').buffer as ArrayBuffer
    const signature = await sign(signer.privateKey, data)
    const valid = await verify(verifier.publicKey, signature, data)
    expect(valid).toBe(false)
  })
})
