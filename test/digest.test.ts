import { describe, it, expect } from 'vitest'
import { digest } from '../src/digest'

describe('digest', () => {
  it('returns an ArrayBuffer', async () => {
    const result = await digest(new TextEncoder().encode('hello'))
    expect(result).toBeInstanceOf(ArrayBuffer)
  })

  it('produces a 32-byte SHA-256 hash', async () => {
    const result = await digest(new TextEncoder().encode('hello'))
    expect(result.byteLength).toBe(32)
  })

  it('is deterministic', async () => {
    const a = await digest(new TextEncoder().encode('conseal'))
    const b = await digest(new TextEncoder().encode('conseal'))
    expect(Array.from(new Uint8Array(a))).toEqual(Array.from(new Uint8Array(b)))
  })

  it('produces different hashes for different inputs', async () => {
    const a = await digest(new TextEncoder().encode('foo'))
    const b = await digest(new TextEncoder().encode('bar'))
    expect(Array.from(new Uint8Array(a))).not.toEqual(Array.from(new Uint8Array(b)))
  })

  it('accepts Uint8Array input', async () => {
    const a = await digest(new TextEncoder().encode('test'))
    const b = await digest(new TextEncoder().encode('test').buffer as ArrayBuffer)
    expect(Array.from(new Uint8Array(a))).toEqual(Array.from(new Uint8Array(b)))
  })
})
