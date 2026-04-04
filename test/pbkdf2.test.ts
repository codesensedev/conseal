import { describe, it, expect } from 'vitest'
import { wrapKey, unwrapKey, rekey, rekeySecretKey } from '../src/pbkdf2'
import { generateSecretKey } from '../src/secret-key'

/** Generates a fresh extractable AES-256-GCM key. extractable: true is required
 *  for wrapKey() — SubtleCrypto cannot wrap a non-extractable key. */
async function makeAEK(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // must be extractable to wrap
    ['encrypt', 'decrypt']
  )
}

describe('wrapKey / unwrapKey', () => {
  it('round-trips a key through wrap/unwrap', async () => {
    const aek = await makeAEK()
    const { wrappedKey, salt } = await wrapKey('correct-passphrase', aek)
    const recovered = await unwrapKey('correct-passphrase', wrappedKey, salt)
    // Verify the recovered key works: encrypt with original, decrypt with recovered
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const plaintext = new TextEncoder().encode('test').buffer as ArrayBuffer
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aek, plaintext)
    const result = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, recovered, ciphertext)
    expect(new TextDecoder().decode(result)).toBe('test')
  }, 10_000)

  it('produces different salt each call', async () => {
    const aek = await makeAEK()
    const a = await wrapKey('pass', aek)
    const b = await wrapKey('pass', aek)
    expect(Array.from(a.salt)).not.toEqual(Array.from(b.salt))
  }, 10_000)

  it('throws when unwrapping with wrong passphrase', async () => {
    const aek = await makeAEK()
    const { wrappedKey, salt } = await wrapKey('correct', aek)
    await expect(unwrapKey('wrong', wrappedKey, salt)).rejects.toThrow()
  }, 10_000)

  it('returned key from unwrapKey is non-extractable', async () => {
    const aek = await makeAEK()
    const { wrappedKey, salt } = await wrapKey('pass', aek)
    const recovered = await unwrapKey('pass', wrappedKey, salt)
    expect(recovered.extractable).toBe(false)
  }, 10_000)

  it('throws when wrapping a non-extractable key', async () => {
    const nonExtractable = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )
    await expect(wrapKey('pass', nonExtractable)).rejects.toThrow()
  })

  it('round-trips a key through wrap/unwrap with a secret key', async () => {
    const aek = await makeAEK()
    const sk = generateSecretKey()
    const { wrappedKey, salt } = await wrapKey('correct-passphrase', aek, sk)
    const recovered = await unwrapKey('correct-passphrase', wrappedKey, salt, sk)
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const plaintext = new TextEncoder().encode('test-sk').buffer as ArrayBuffer
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aek, plaintext)
    const result = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, recovered, ciphertext)
    expect(new TextDecoder().decode(result)).toBe('test-sk')
  }, 15_000)

  it('throws when unwrapping with wrong secret key', async () => {
    const aek = await makeAEK()
    const sk = generateSecretKey()
    const { wrappedKey, salt } = await wrapKey('correct-passphrase', aek, sk)
    const wrongSk = generateSecretKey()
    await expect(unwrapKey('correct-passphrase', wrappedKey, salt, wrongSk)).rejects.toThrow()
  }, 15_000)

  it('throws when unwrapping without secret key a key wrapped with one', async () => {
    const aek = await makeAEK()
    const sk = generateSecretKey()
    const { wrappedKey, salt } = await wrapKey('passphrase', aek, sk)
    await expect(unwrapKey('passphrase', wrappedKey, salt)).rejects.toThrow()
  }, 15_000)

  it('throws when unwrapping with secret key a key wrapped without one', async () => {
    const aek = await makeAEK()
    const { wrappedKey, salt } = await wrapKey('passphrase', aek)
    const sk = generateSecretKey()
    await expect(unwrapKey('passphrase', wrappedKey, salt, sk)).rejects.toThrow()
  }, 15_000)
})

describe('rekey', () => {
  it('changes passphrase — new passphrase decrypts, old does not', async () => {
    const aek = await makeAEK()

    // Encrypt something with the original AEK before rekeying
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const plaintext = new TextEncoder().encode('preserved data').buffer as ArrayBuffer
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aek, plaintext)

    const { wrappedKey, salt } = await wrapKey('old-pass', aek)
    const { wrappedKey: newWrapped, salt: newSalt } = await rekey('old-pass', 'new-pass', wrappedKey, salt)

    // Recovered key must decrypt data encrypted by the original AEK
    const recovered = await unwrapKey('new-pass', newWrapped, newSalt)
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, recovered, ciphertext)
    expect(new TextDecoder().decode(decrypted)).toBe('preserved data')

    // Old passphrase must fail on the new wrapped key
    await expect(unwrapKey('old-pass', newWrapped, newSalt)).rejects.toThrow()
  }, 30_000)

  it('throws when old passphrase is wrong', async () => {
    const aek = await makeAEK()
    const { wrappedKey, salt } = await wrapKey('correct', aek)
    await expect(rekey('wrong', 'new-pass', wrappedKey, salt)).rejects.toThrow()
  }, 15_000)
})

describe('rekey with secret key', () => {
  it('changes passphrase — new passphrase + same SK decrypts, old passphrase fails', async () => {
    const aek = await makeAEK()
    const sk = generateSecretKey()

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const plaintext = new TextEncoder().encode('preserved').buffer as ArrayBuffer
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aek, plaintext)

    const { wrappedKey, salt } = await wrapKey('old-pass', aek, sk)
    const { wrappedKey: newWrapped, salt: newSalt } = await rekey('old-pass', 'new-pass', wrappedKey, salt, sk)

    const recovered = await unwrapKey('new-pass', newWrapped, newSalt, sk)
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, recovered, ciphertext)
    expect(new TextDecoder().decode(decrypted)).toBe('preserved')

    await expect(unwrapKey('old-pass', newWrapped, newSalt, sk)).rejects.toThrow()
  }, 30_000)

  it('throws when old passphrase is wrong', async () => {
    const aek = await makeAEK()
    const sk = generateSecretKey()
    const { wrappedKey, salt } = await wrapKey('correct', aek, sk)
    await expect(rekey('wrong', 'new-pass', wrappedKey, salt, sk)).rejects.toThrow()
  }, 15_000)
})

describe('rekeySecretKey', () => {
  it('new secret key decrypts, old secret key fails', async () => {
    const aek = await makeAEK()
    const oldSk = generateSecretKey()
    const newSk = generateSecretKey()

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const plaintext = new TextEncoder().encode('preserved').buffer as ArrayBuffer
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aek, plaintext)

    const { wrappedKey, salt } = await wrapKey('my-passphrase', aek, oldSk)
    const { wrappedKey: newWrapped, salt: newSalt } = await rekeySecretKey('my-passphrase', oldSk, newSk, wrappedKey, salt)

    const recovered = await unwrapKey('my-passphrase', newWrapped, newSalt, newSk)
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, recovered, ciphertext)
    expect(new TextDecoder().decode(decrypted)).toBe('preserved')

    await expect(unwrapKey('my-passphrase', newWrapped, newSalt, oldSk)).rejects.toThrow()
  }, 30_000)

  it('throws when passphrase is wrong', async () => {
    const aek = await makeAEK()
    const oldSk = generateSecretKey()
    const newSk = generateSecretKey()
    const { wrappedKey, salt } = await wrapKey('correct', aek, oldSk)
    await expect(rekeySecretKey('wrong', oldSk, newSk, wrappedKey, salt)).rejects.toThrow()
  }, 15_000)

  it('throws when old secret key is wrong', async () => {
    const aek = await makeAEK()
    const oldSk = generateSecretKey()
    const wrongSk = generateSecretKey()
    const newSk = generateSecretKey()
    const { wrappedKey, salt } = await wrapKey('passphrase', aek, oldSk)
    await expect(rekeySecretKey('passphrase', wrongSk, newSk, wrappedKey, salt)).rejects.toThrow()
  }, 15_000)

  it('throws when oldSecretKey and newSecretKey are identical', async () => {
    const aek = await makeAEK()
    const sk = generateSecretKey()
    const { wrappedKey, salt } = await wrapKey('passphrase', aek, sk)
    await expect(rekeySecretKey('passphrase', sk, sk, wrappedKey, salt)).rejects.toThrow(
      'rekeySecretKey: oldSecretKey and newSecretKey must be different'
    )
  })
})
