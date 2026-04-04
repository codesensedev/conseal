/**
 * Known-answer tests (KATs) using NIST CAVP and RFC test vectors.
 *
 * These tests call SubtleCrypto directly — they are independent of Conseal's
 * higher-level logic and prove the SubtleCrypto primitive wiring is correct.
 *
 * Run in real browsers to validate against native SubtleCrypto:
 *   npm run test:browser
 *
 * Primitives covered:
 *   - AES-256-GCM   — NIST CAVP GCMEncryptExtIV256 (gcmtestvectors.zip, Count=0 for each PTlen)
 *   - PBKDF2-SHA256  — brycx/Test-Vector-Generation HMAC-SHA-256 vectors
 *                      (cross-validated: @noble/hashes + Chromium + Firefox + WebKit all agree)
 *   - ECDH P-256     — NIST CAVP KAS_ECC_CDH_PrimitiveTest.txt, COUNT=0
 *   - ECDSA P-256    — NIST CAVP 186-3ecdsatestvectors SigVer.rsp [P-256,SHA-256], pass + fail
 *
 * AES-KW is intentionally omitted: WebKit's SubtleCrypto does not enforce the
 * RFC 3394 integrity check on AES-KW unwrap. Conseal uses AES-GCM for key
 * wrapping instead. See the comment in src/pbkdf2.ts.
 */

import { describe, it, expect } from 'vitest'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Hex string → Uint8Array backed by a plain ArrayBuffer (required by SubtleCrypto typings) */
function hex(h: string): Uint8Array<ArrayBuffer> {
  if (!h) return new Uint8Array(0) as Uint8Array<ArrayBuffer>
  return new Uint8Array(h.match(/.{2}/g)!.map(b => parseInt(b, 16))) as Uint8Array<ArrayBuffer>
}

/** ArrayBuffer | Uint8Array → lowercase hex string */
function toHex(buf: ArrayBuffer | Uint8Array): string {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  return Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('')
}

/** Hex string → base64url — used to build JWK coordinate fields */
function hexToB64u(h: string): string {
  const bytes = hex(h)
  let bin = ''
  bytes.forEach(b => (bin += String.fromCharCode(b)))
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

// ---------------------------------------------------------------------------
// AES-256-GCM — NIST CAVP GCMEncryptExtIV256
// Source: gcmtestvectors.zip > gcmEncryptExtIV256.rsp
// Parameters: Keylen=256, IVlen=96, Taglen=128, AADlen=0
// SubtleCrypto appends the 16-byte auth tag directly after the ciphertext bytes.
// ---------------------------------------------------------------------------

describe('AES-256-GCM — NIST CAVP GCMEncryptExtIV256', () => {
  // Count=0, PTlen=0 (empty plaintext)
  // Key = b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4
  // IV  = 516c33929df5a3284ff463d7
  // PT  = (empty)
  // CT  = (empty)
  // Tag = bdc1ac884d332457a1d2664f168c76f0
  it('Count=0 PTlen=0 — empty plaintext produces correct auth tag', async () => {
    const key = await crypto.subtle.importKey(
      'raw', hex('b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4'),
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    )
    const iv = hex('516c33929df5a3284ff463d7')
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, hex(''))
    expect(toHex(ct)).toBe('bdc1ac884d332457a1d2664f168c76f0')
  })

  it('Count=0 PTlen=0 — decrypt recovers empty plaintext', async () => {
    const key = await crypto.subtle.importKey(
      'raw', hex('b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4'),
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    )
    const iv = hex('516c33929df5a3284ff463d7')
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 }, key, hex('bdc1ac884d332457a1d2664f168c76f0')
    )
    expect(pt.byteLength).toBe(0)
  })

  // Count=0, PTlen=128 (16-byte plaintext)
  // Key = 31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22
  // IV  = 0d18e06c7c725ac9e362e1ce
  // PT  = 2db5168e932556f8089a0622981d017d
  // CT  = fa4362189661d163fcd6a56d8bf0405a
  // Tag = d636ac1bbedd5cc3ee727dc2ab4a9489
  it('Count=0 PTlen=128 — 16-byte plaintext produces correct ciphertext + tag', async () => {
    const key = await crypto.subtle.importKey(
      'raw', hex('31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22'),
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    )
    const iv = hex('0d18e06c7c725ac9e362e1ce')
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 }, key, hex('2db5168e932556f8089a0622981d017d')
    )
    expect(toHex(ct)).toBe('fa4362189661d163fcd6a56d8bf0405ad636ac1bbedd5cc3ee727dc2ab4a9489')
  })

  it('Count=0 PTlen=128 — decrypt recovers 16-byte plaintext', async () => {
    const key = await crypto.subtle.importKey(
      'raw', hex('31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22'),
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    )
    const iv = hex('0d18e06c7c725ac9e362e1ce')
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 }, key,
      hex('fa4362189661d163fcd6a56d8bf0405ad636ac1bbedd5cc3ee727dc2ab4a9489')
    )
    expect(toHex(pt)).toBe('2db5168e932556f8089a0622981d017d')
  })
})

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA256
// Source: brycx/Test-Vector-Generation PBKDF2-HMAC-SHA256 (widely reproduced)
//         cross-validated: @noble/hashes, Chromium, Firefox, and WebKit all agree.
// Note: RFC 6070 covers only PBKDF2-HMAC-SHA1; there is no equivalent SHA-256 RFC.
// Tested via SubtleCrypto deriveBits (same PBKDF2 computation path as Conseal's deriveKey).
// Low iteration counts are used so tests run quickly.
// ---------------------------------------------------------------------------

describe('PBKDF2-HMAC-SHA256', () => {
  async function pbkdf2(password: string, salt: string, iterations: number, dkLenBytes: number): Promise<string> {
    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password),
      'PBKDF2', false, ['deriveBits']
    )
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations, hash: 'SHA-256' },
      keyMaterial,
      dkLenBytes * 8
    )
    return toHex(bits)
  }

  // P="password", S="salt", c=1, dkLen=32
  it('vector 1 — password/salt/c=1', async () => {
    const dk = await pbkdf2('password', 'salt', 1, 32)
    expect(dk).toBe('120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b')
  }, 10_000)

  // P="password", S="salt", c=2, dkLen=32
  it('vector 2 — password/salt/c=2', async () => {
    const dk = await pbkdf2('password', 'salt', 2, 32)
    expect(dk).toBe('ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43')
  }, 10_000)

  // P="passwordPASSWORDpassword", S="saltSALTsaltSALTsaltSALTsaltSALTsalt", c=4096, dkLen=40
  it('vector 3 — longer inputs/c=4096', async () => {
    const dk = await pbkdf2('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 40)
    expect(dk).toBe('348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9')
  }, 30_000)
})

// ---------------------------------------------------------------------------
// ECDH P-256 — NIST CAVP KAS ECC CDH Primitive
// Source: ecccdhtestvectors.zip > KAS_ECC_CDH_PrimitiveTest.txt, [P-256] COUNT=0
//
// The IUT computes the shared secret using its private key (dIUT) and the
// CAVS party's public key (QCAVSx, QCAVSy). SubtleCrypto's ECDH deriveBits
// returns the x-coordinate of the shared point, which equals ZIUT.
// ---------------------------------------------------------------------------

describe('ECDH P-256 — NIST CAVP KAS_ECC_CDH_PrimitiveTest COUNT=0', () => {
  // IUT private key
  const privIUTJwk: JsonWebKey = {
    kty: 'EC', crv: 'P-256',
    d:  hexToB64u('7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534'),
    x:  hexToB64u('ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230'),
    y:  hexToB64u('28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141'),
  }

  // CAVS party's public key
  const pubCAVSJwk: JsonWebKey = {
    kty: 'EC', crv: 'P-256',
    x: hexToB64u('700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287'),
    y: hexToB64u('db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac'),
  }

  // Expected shared secret (x-coordinate of shared EC point)
  const expectedZIUT = '46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b'

  it('ECDH(privIUT, pubCAVS) produces ZIUT', async () => {
    const privIUT = await crypto.subtle.importKey('jwk', privIUTJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
    const pubCAVS = await crypto.subtle.importKey('jwk', pubCAVSJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: pubCAVS }, privIUT, 256)
    expect(toHex(shared)).toBe(expectedZIUT)
  })
})

// ---------------------------------------------------------------------------
// ECDSA P-256 — NIST CAVP 186-3ecdsatestvectors SigVer
// Source: 186-3ecdsatestvectors.zip > SigVer.rsp, [P-256,SHA-256]
//
// SubtleCrypto ECDSA verify takes the raw message (not its hash) — SHA-256
// hashing is applied internally by the algorithm.
// Signature format: raw IEEE P1363 = R || S (each 32 bytes, 64 bytes total).
// ---------------------------------------------------------------------------

describe('ECDSA P-256 — NIST CAVP SigVer [P-256,SHA-256]', () => {
  // Pass vector (Result = P)
  // Msg, Qx, Qy, R, S from SigVer.rsp
  it('pass vector — valid signature verifies as true', async () => {
    const pubKey = await crypto.subtle.importKey(
      'jwk',
      {
        kty: 'EC', crv: 'P-256',
        x: hexToB64u('e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c'),
        y: hexToB64u('970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927'),
      },
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
    )
    const sig = hex(
      'bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f' +
      '17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c'
    )
    const msg = hex('e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3')
    const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, sig, msg)
    expect(valid).toBe(true)
  })

  // Fail vector (Result = F, reason: S changed)
  it('fail vector — tampered signature verifies as false', async () => {
    const pubKey = await crypto.subtle.importKey(
      'jwk',
      {
        kty: 'EC', crv: 'P-256',
        x: hexToB64u('87f8f2b218f49845f6f10eec3877136269f5c1a54736dbdf69f89940cad41555'),
        y: hexToB64u('e15f369036f49842fac7a86c8a2b0557609776814448b8f5e84aa9f4395205e9'),
      },
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
    )
    const sig = hex(
      'd19ff48b324915576416097d2544f7cbdf8768b1454ad20e0baac50e211f23b0' +
      'a3e81e59311cdfff2d4784949f7a2cb50ba6c3a91fa54710568e61aca3e847c6'
    )
    const msg = hex('e4796db5f785f207aa30d311693b3702821dff1168fd2e04c0836825aefd850d9aa60326d88cde1a23c7745351392ca2288d632c264f197d05cd424a30336c19fd09bb229654f0222fcb881a4b35c290a093ac159ce13409111ff0358411133c24f5b8e2090d6db6558afc36f06ca1f6ef779785adba68db27a409859fc4c4a0')
    const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, sig, msg)
    expect(valid).toBe(false)
  })
})
