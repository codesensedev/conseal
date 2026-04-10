// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Codesense

/**
 * Constant-time buffer comparison.
 *
 * Single implementation shared across pbkdf2.ts and circle.ts to prevent
 * divergence between slightly different local copies.
 */

/** Compares two Uint8Arrays in constant time. Returns true if they are equal. */
export function buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let result = 0
  for (let i = 0; i < a.length; i++) result |= (a[i] as number) ^ (b[i] as number)
  return result === 0
}
