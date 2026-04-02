import { describe, it, expect } from 'vitest'
import { toBase64, fromBase64, toBase64Url, fromBase64Url } from '../src/base64'

describe('toBase64 / fromBase64', () => {
  it('round-trips an ArrayBuffer', () => {
    const original = new TextEncoder().encode('hello base64').buffer as ArrayBuffer
    expect(new TextDecoder().decode(fromBase64(toBase64(original)))).toBe('hello base64')
  })

  it('round-trips a Uint8Array', () => {
    const original = new TextEncoder().encode('hello from uint8')
    const result = fromBase64(toBase64(original))
    expect(new TextDecoder().decode(result)).toBe('hello from uint8')
  })

  it('produces the correct base64 string', () => {
    const buf = new Uint8Array([72, 101, 108, 108, 111]) // "Hello"
    expect(toBase64(buf)).toBe('SGVsbG8=')
  })

  it('decodes a known base64 string', () => {
    const result = new Uint8Array(fromBase64('SGVsbG8='))
    expect(Array.from(result)).toEqual([72, 101, 108, 108, 111])
  })

  it('handles empty input', () => {
    expect(toBase64(new ArrayBuffer(0))).toBe('')
    expect(fromBase64('').byteLength).toBe(0)
  })
})

describe('toBase64Url / fromBase64Url', () => {
  it('round-trips an ArrayBuffer', () => {
    const original = new TextEncoder().encode('hello base64url').buffer as ArrayBuffer
    const result = fromBase64Url(toBase64Url(original))
    expect(new TextDecoder().decode(result)).toBe('hello base64url')
  })

  it('produces no +, /, or = characters', () => {
    // Use enough data to statistically guarantee padding and +/- ambiguous chars appear
    const buf = new Uint8Array(64).map((_, i) => i)
    const encoded = toBase64Url(buf)
    expect(encoded).not.toMatch(/[+/=]/)
  })

  it('uses - and _ instead of + and /', () => {
    // 0xfb = produces + in standard base64; 0xff produces /
    const buf = new Uint8Array([0xfb, 0xff])
    const std = toBase64(buf)
    const url = toBase64Url(buf)
    // Standard base64 uses + and /
    expect(std).toMatch(/[+/]/)
    // URL-safe replaces them
    expect(url).not.toMatch(/[+/=]/)
  })

  it('fromBase64Url returns a Uint8Array', () => {
    const result = fromBase64Url('SGVsbG8')
    expect(result).toBeInstanceOf(Uint8Array)
  })

  it('decodes a known base64url string (no padding)', () => {
    // "Hello" in base64 is "SGVsbG8=" — base64url drops the =
    const result = fromBase64Url('SGVsbG8')
    expect(new TextDecoder().decode(result)).toBe('Hello')
  })

  it('handles empty input', () => {
    expect(toBase64Url(new ArrayBuffer(0))).toBe('')
    expect(fromBase64Url('').byteLength).toBe(0)
  })
})
