import { describe, it, expect } from 'vitest'
import { generateSecretKey, combinePassphraseAndSecretKey } from '../src/secret-key'
import { toBase64 } from '../src/base64'

describe('generateSecretKey', () => {
  it('returns a Uint8Array of exactly 16 bytes', () => {
    const sk = generateSecretKey()
    expect(sk).toBeInstanceOf(Uint8Array)
    expect(sk.length).toBe(16)
  })

  it('produces different values on each call', () => {
    const a = generateSecretKey()
    const b = generateSecretKey()
    expect(Array.from(a)).not.toEqual(Array.from(b))
  })
})

describe('combinePassphraseAndSecretKey', () => {
  it('is deterministic — same inputs produce the same output', async () => {
    const sk = generateSecretKey()
    const a = await combinePassphraseAndSecretKey('my-passphrase', sk)
    const b = await combinePassphraseAndSecretKey('my-passphrase', sk)
    expect(a).toBe(b)
  })

  it('different passphrase produces different output', async () => {
    const sk = generateSecretKey()
    const a = await combinePassphraseAndSecretKey('passphrase-A', sk)
    const b = await combinePassphraseAndSecretKey('passphrase-B', sk)
    expect(a).not.toBe(b)
  })

  it('different secret key produces different output', async () => {
    const skA = generateSecretKey()
    const skB = generateSecretKey()
    const a = await combinePassphraseAndSecretKey('same-passphrase', skA)
    const b = await combinePassphraseAndSecretKey('same-passphrase', skB)
    expect(a).not.toBe(b)
  })

  it('output does not contain the passphrase as a substring', async () => {
    const passphrase = 'my-secret-pass'
    const sk = generateSecretKey()
    const combined = await combinePassphraseAndSecretKey(passphrase, sk)
    expect(combined).not.toContain(passphrase)
  })

  it('output does not contain the base64 secret key as a substring', async () => {
    const sk = generateSecretKey()
    const combined = await combinePassphraseAndSecretKey('my-passphrase', sk)
    expect(combined).not.toContain(toBase64(sk))
  })

  it('returns a 64-character hex string (SHA-256 output)', async () => {
    const sk = generateSecretKey()
    const combined = await combinePassphraseAndSecretKey('pass', sk)
    expect(combined).toMatch(/^[0-9a-f]{64}$/)
  })
})
