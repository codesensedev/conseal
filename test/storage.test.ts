import { describe, it, expect, beforeEach } from 'vitest'
import { save, load, remove } from '../src/storage'

/** Clear the database before each test to prevent cross-test contamination. */
beforeEach(async () => {
  const deletePromise = new Promise<void>((resolve) => {
    const req = indexedDB.deleteDatabase('conseal-keys')
    req.onsuccess = () => {
      resolve()
    }
    req.onerror = () => {
      // It's OK if deletion fails (e.g., database doesn't exist)
      resolve()
    }
    req.onblocked = () => {
      // Ignore blocked notifications
    }
  })

  // Add a timeout to prevent hanging
  await Promise.race([
    deletePromise,
    new Promise<void>((_, reject) =>
      setTimeout(() => reject(new Error('deleteDatabase timeout')), 5000)
    ),
  ]).catch(() => {
    // Ignore errors and timeouts in cleanup
  })
})

async function makeKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

describe('save / load', () => {
  it('saves a key and loads it back', async () => {
    const key = await makeKey()
    await save('my-key', key)
    const loaded = await load('my-key')
    expect(loaded).not.toBeNull()
    expect(loaded!.type).toBe('secret')
    expect(loaded!.algorithm).toMatchObject({ name: 'AES-GCM' })
  })

  it('returns null for a key that was never saved', async () => {
    const result = await load('nonexistent')
    expect(result).toBeNull()
  })

  it('overwrites an existing key when saved with the same name', async () => {
    const key1 = await makeKey()
    const key2 = await makeKey()
    await save('same-id', key1)
    await save('same-id', key2)
    const loaded = await load('same-id')
    // key2 should be stored; we verify it encrypts/decrypts correctly
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const data = new TextEncoder().encode('test').buffer as ArrayBuffer
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key2, data)
    const result = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, loaded!, ciphertext)
    expect(new TextDecoder().decode(result)).toBe('test')
  })
})

describe('remove', () => {
  it('removes a saved key', async () => {
    const key = await makeKey()
    await save('to-delete', key)
    await remove('to-delete')
    const result = await load('to-delete')
    expect(result).toBeNull()
  })

  it('does not throw when removing a non-existent key', async () => {
    await expect(remove('ghost')).resolves.toBeUndefined()
  })
})
