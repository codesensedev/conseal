// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * Base64 encoding and decoding utilities.
 *
 * Helper functions for converting between binary data (ArrayBuffer / Uint8Array)
 * and standard base64 strings — used when serialising encrypted payloads for
 * storage or transmission over text-based channels.
 *
 * Two variants are provided:
 *   toBase64 / fromBase64       — standard base64 (uses +, /, = padding)
 *   toBase64Url / fromBase64Url — base64url (uses -, _, no padding; safe in URLs and JWKs)
 */

/**
 * Encodes an ArrayBuffer or Uint8Array to a standard base64 string.
 * Uses a loop instead of spread to avoid stack overflow on large buffers.
 */
export function toBase64(buf: ArrayBuffer | Uint8Array): string {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let binary = ''
  for (const byte of u8) binary += String.fromCharCode(byte)
  return btoa(binary)
}

/** Decodes a standard base64 string to a Uint8Array. */
export function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
}

/**
 * Encodes an ArrayBuffer or Uint8Array to a base64url string.
 * Replaces + with -, / with _, and strips = padding.
 * Used for JWK coordinates and URL-safe contexts.
 */
export function toBase64Url(buf: ArrayBuffer | Uint8Array): string {
  return toBase64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

/** Decodes a base64url string to a Uint8Array. */
export function fromBase64Url(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/')
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
}
