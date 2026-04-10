import { describe, it, expect } from 'vitest'
import { exportPublicKeyAsJwk, importPublicKeyFromJwk } from '../src/jwk'

describe('exportPublicKeyAsJwk / importPublicKeyFromJwk', () => {
  it('exports an ECDH public key as JWK and re-imports it', async () => {
    const { publicKey } = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey']
    )
    const jwk = await exportPublicKeyAsJwk(publicKey)
    expect(jwk.kty).toBe('EC')
    expect(jwk.crv).toBe('P-256')
    const imported = await importPublicKeyFromJwk(jwk, 'ECDH')
    expect(imported.type).toBe('public')
    expect(imported.algorithm).toMatchObject({ name: 'ECDH', namedCurve: 'P-256' })
  })

  it('exports an ECDSA public key as JWK and re-imports it', async () => {
    const { publicKey } = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    )
    const jwk = await exportPublicKeyAsJwk(publicKey)
    expect(jwk.kty).toBe('EC')
    expect(jwk.crv).toBe('P-256')
    const imported = await importPublicKeyFromJwk(jwk, 'ECDSA')
    expect(imported.type).toBe('public')
    expect(imported.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' })
  })

  it('imported ECDSA key can verify a signature', async () => {
    const { publicKey, privateKey } = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    )
    const data = new TextEncoder().encode('hello').buffer as ArrayBuffer
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data)
    const jwk = await exportPublicKeyAsJwk(publicKey)
    const imported = await importPublicKeyFromJwk(jwk, 'ECDSA')
    const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, imported, signature, data)
    expect(valid).toBe(true)
  })

  it('throws when x is missing from the JWK', async () => {
    const { publicKey } = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey']
    )
    const jwk = await exportPublicKeyAsJwk(publicKey)
    const { x: _x, ...missingX } = jwk
    await expect(importPublicKeyFromJwk(missingX, 'ECDH')).rejects.toThrow()
  })

  it('throws when y is missing from the JWK', async () => {
    const { publicKey } = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey']
    )
    const jwk = await exportPublicKeyAsJwk(publicKey)
    const { y: _y, ...missingY } = jwk
    await expect(importPublicKeyFromJwk(missingY, 'ECDH')).rejects.toThrow()
  })

  it('throws when crv is missing from the JWK', async () => {
    const { publicKey } = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey']
    )
    const jwk = await exportPublicKeyAsJwk(publicKey)
    const { crv: _crv, ...missingCrv } = jwk
    await expect(importPublicKeyFromJwk(missingCrv, 'ECDH')).rejects.toThrow()
  })
})
