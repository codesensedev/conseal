// ═══════════════════════════════════════════════════════════════════════
// GLOBALS FROM IIFE BUNDLES
// ═══════════════════════════════════════════════════════════════════════

const { mnemonicToEntropy, wordlist } = bip39

// ═══════════════════════════════════════════════════════════════════════
// THEME
// ═══════════════════════════════════════════════════════════════════════

function initTheme() {
  const savedTheme = localStorage.getItem('conseal-theme')
  if (savedTheme) {
    setTheme(savedTheme)
  } else {
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
    setTheme(prefersDark ? 'dark' : 'light')
  }
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme)
  const themeBtn = document.querySelector('.theme-toggle')
  if (themeBtn) themeBtn.textContent = theme === 'dark' ? '☾' : '☀'
  localStorage.setItem('conseal-theme', theme)
}

function toggleTheme() {
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark'
  setTheme(isDark ? 'light' : 'dark')
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initTheme)
} else {
  initTheme()
}

// ═══════════════════════════════════════════════════════════════════════
// TAB SWITCHING
// ═══════════════════════════════════════════════════════════════════════

function activateTab(tab) {
  const btn = document.querySelector(`.tab-btn[data-tab="${tab}"]`)
  if (!btn) return
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b === btn))
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `tab-${tab}`))
}

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.tab
    history.replaceState(null, '', `#${target}`)
    activateTab(target)
  })
})

// Activate tab from URL hash on load, default to 'seal'
const initialTab = location.hash.slice(1)
activateTab((initialTab && document.querySelector(`.tab-btn[data-tab="${initialTab}"]`)) ? initialTab : 'seal')

// ═══════════════════════════════════════════════════════════════════════
// SHARED UTILITIES
// ═══════════════════════════════════════════════════════════════════════

function setStatus(el, type, msg) {
  el.className = `status ${type}`
  el.textContent = msg
}

function clearStatus(el) {
  el.className = 'status'
  el.textContent = ''
}

// ═══════════════════════════════════════════════════════════════════════
// TAB: SEAL / UNSEAL
// ═══════════════════════════════════════════════════════════════════════

document.getElementById('seal-btn').addEventListener('click', async () => {
  const plaintext  = document.getElementById('seal-plain').value
  const passcode   = document.getElementById('seal-passcode').value
  const statusEl   = document.getElementById('seal-status')
  const outputEl   = document.getElementById('seal-output')
  const copyBtn    = document.getElementById('seal-copy')
  const btn        = document.getElementById('seal-btn')

  clearStatus(statusEl)
  outputEl.value = ''
  copyBtn.style.display = 'none'

  if (!plaintext.trim()) { setStatus(statusEl, 'error', 'Enter some text to encrypt.'); return }
  if (!passcode)          { setStatus(statusEl, 'error', 'Enter a passcode.'); return }

  btn.disabled = true
  btn.textContent = 'Sealing…'

  try {
    const encoded = new TextEncoder().encode(plaintext)
    const result  = await conseal.sealEnvelope(encoded.buffer, passcode)
    outputEl.value = conseal.encodeEnvelope(result)
    copyBtn.style.display = 'block'
    setStatus(statusEl, 'ok', 'Sealed. Copy the payload and paste it into the Unseal panel.')
  } catch (err) {
    setStatus(statusEl, 'error', `Error: ${err.message}`)
  } finally {
    btn.disabled = false
    btn.textContent = 'Seal →'
  }
})

document.getElementById('seal-copy').addEventListener('click', () => {
  const text = document.getElementById('seal-output').value
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById('seal-copy')
    btn.textContent = 'Copied!'
    setTimeout(() => btn.textContent = 'Copy', 1500)
  })
})

document.getElementById('unseal-btn').addEventListener('click', async () => {
  const payload   = document.getElementById('unseal-input').value.trim()
  const passcode  = document.getElementById('unseal-passcode').value
  const statusEl  = document.getElementById('unseal-status')
  const outputEl  = document.getElementById('unseal-output')
  const btn       = document.getElementById('unseal-btn')

  clearStatus(statusEl)
  outputEl.value = ''

  if (!payload)  { setStatus(statusEl, 'error', 'Paste an encrypted payload.'); return }
  if (!passcode) { setStatus(statusEl, 'error', 'Enter the passcode.'); return }

  btn.disabled = true
  btn.textContent = 'Unsealing…'

  try {
    const { ciphertext, iv, wrappedKey, salt } = conseal.decodeEnvelope(payload)
    const result = await conseal.unsealEnvelope({ ciphertext, iv, wrappedKey, salt }, passcode)
    outputEl.value = new TextDecoder().decode(result)
    setStatus(statusEl, 'ok', 'Unsealed successfully.')
  } catch (err) {
    if (err.name === 'OperationError' || err.message?.includes('unwrap')) {
      setStatus(statusEl, 'error', 'Wrong passcode or corrupted payload.')
    } else if (err instanceof SyntaxError) {
      setStatus(statusEl, 'error', 'Invalid payload — expected JSON.')
    } else {
      setStatus(statusEl, 'error', `Error: ${err.message}`)
    }
  } finally {
    btn.disabled = false
    btn.textContent = 'Unseal →'
  }
})

// ═══════════════════════════════════════════════════════════════════════
// TAB: FILES
// ═══════════════════════════════════════════════════════════════════════

// .cnsl binary layout:
//   [4 bytes]  magic "CNSL"
//   [1 byte]   version = 1
//   [2 bytes]  original filename length (uint16 BE)
//   [N bytes]  original filename (UTF-8)
//   [16 bytes] salt
//   [12 bytes] iv
//   [2 bytes]  wrappedKey length (uint16 BE)
//   [M bytes]  wrappedKey
//   [rest]     ciphertext

const MAGIC = [0x43, 0x4e, 0x53, 0x4c] // "CNSL"
const VERSION = 1

function packCnsl(filename, salt, iv, wrappedKey, ciphertext) {
  const nameBytes = new TextEncoder().encode(filename)
  const wrappedKeyBytes = new Uint8Array(wrappedKey)
  const header = new Uint8Array(4 + 1 + 2 + nameBytes.length + 16 + 12 + 2 + wrappedKeyBytes.length)
  let offset = 0
  header.set(MAGIC, offset); offset += 4
  header[offset++] = VERSION
  header[offset++] = (nameBytes.length >> 8) & 0xff
  header[offset++] = nameBytes.length & 0xff
  header.set(nameBytes, offset); offset += nameBytes.length
  header.set(salt, offset); offset += 16
  header.set(iv, offset); offset += 12
  header[offset++] = (wrappedKeyBytes.length >> 8) & 0xff
  header[offset++] = wrappedKeyBytes.length & 0xff
  header.set(wrappedKeyBytes, offset); offset += wrappedKeyBytes.length
  const out = new Uint8Array(header.length + ciphertext.byteLength)
  out.set(header)
  out.set(new Uint8Array(ciphertext), header.length)
  return out.buffer
}

function unpackCnsl(buffer) {
  const bytes = new Uint8Array(buffer)
  let offset = 0
  for (let i = 0; i < 4; i++) {
    if (bytes[offset++] !== MAGIC[i]) throw new Error('Not a valid .cnsl file')
  }
  const version = bytes[offset++]
  if (version !== VERSION) throw new Error(`Unsupported .cnsl version: ${version}`)
  const nameLen = (bytes[offset++] << 8) | bytes[offset++]
  const filename = new TextDecoder().decode(bytes.slice(offset, offset + nameLen))
  offset += nameLen
  const salt = bytes.slice(offset, offset + 16); offset += 16
  const iv = bytes.slice(offset, offset + 12); offset += 12
  const wrappedKeyLen = (bytes[offset++] << 8) | bytes[offset++]
  const wrappedKey = bytes.slice(offset, offset + wrappedKeyLen).buffer; offset += wrappedKeyLen
  const ciphertext = buffer.slice(offset)
  return { filename, salt, iv, wrappedKey, ciphertext }
}

function downloadBuffer(buffer, filename, mimeType = 'application/octet-stream') {
  const blob = new Blob([buffer], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 5000)
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function setProgress(fillEl, barEl, pct) {
  if (pct == null) {
    barEl.classList.remove('visible')
    fillEl.style.width = '0%'
  } else {
    barEl.classList.add('visible')
    fillEl.style.width = `${pct}%`
  }
}

function wireDropzone(dropEl, inputEl, nameEl, sizeEl, infoEl) {
  let selectedFile = null
  const updateInfo = (file) => {
    selectedFile = file
    nameEl.textContent = file.name
    sizeEl.textContent = formatSize(file.size)
    infoEl.classList.add('visible')
    dropEl.querySelector('.icon').textContent = '📎'
  }
  dropEl.addEventListener('click', () => inputEl.click())
  inputEl.addEventListener('change', () => { if (inputEl.files[0]) updateInfo(inputEl.files[0]) })
  dropEl.addEventListener('dragover', e => { e.preventDefault(); dropEl.classList.add('drag-over') })
  dropEl.addEventListener('dragleave', () => dropEl.classList.remove('drag-over'))
  dropEl.addEventListener('drop', e => {
    e.preventDefault()
    dropEl.classList.remove('drag-over')
    if (e.dataTransfer.files[0]) updateInfo(e.dataTransfer.files[0])
  })
  return () => selectedFile
}

const getEncryptFile = wireDropzone(
  document.getElementById('encrypt-drop'),
  document.getElementById('encrypt-file'),
  document.getElementById('encrypt-file-name'),
  document.getElementById('encrypt-file-size'),
  document.getElementById('encrypt-file-info')
)

const getDecryptFile = wireDropzone(
  document.getElementById('decrypt-drop'),
  document.getElementById('decrypt-file'),
  document.getElementById('decrypt-file-name'),
  document.getElementById('decrypt-file-size'),
  document.getElementById('decrypt-file-info')
)

document.getElementById('encrypt-btn').addEventListener('click', async () => {
  const file     = getEncryptFile()
  const passcode = document.getElementById('encrypt-passcode').value
  const statusEl = document.getElementById('encrypt-status')
  const btn      = document.getElementById('encrypt-btn')
  const fillEl   = document.getElementById('encrypt-progress-fill')
  const barEl    = document.getElementById('encrypt-progress')

  clearStatus(statusEl)
  if (!file)                        { setStatus(statusEl, 'error', 'Select a file to encrypt.'); return }
  if (file.size > 1 * 1024 * 1024) { setStatus(statusEl, 'error', 'File exceeds 1 MB limit.'); return }
  if (!passcode)                    { setStatus(statusEl, 'error', 'Enter a passcode.'); return }

  btn.disabled = true
  btn.textContent = 'Encrypting…'
  setProgress(fillEl, barEl, 20)

  try {
    const plaintext = await file.arrayBuffer()
    setProgress(fillEl, barEl, 50)
    const { ciphertext, iv, wrappedKey, salt } = await conseal.sealEnvelope(plaintext, passcode)
    setProgress(fillEl, barEl, 90)
    const packed = packCnsl(file.name, salt, iv, wrappedKey, ciphertext)
    setProgress(fillEl, barEl, 100)
    downloadBuffer(packed, `${file.name}.cnsl`)
    setStatus(statusEl, 'ok', `Encrypted → ${file.name}.cnsl downloaded.`)
  } catch (err) {
    setStatus(statusEl, 'error', `Error: ${err.message}`)
  } finally {
    btn.disabled = false
    btn.textContent = 'Encrypt & Download →'
    setTimeout(() => setProgress(fillEl, barEl, null), 800)
  }
})

document.getElementById('decrypt-btn').addEventListener('click', async () => {
  const file     = getDecryptFile()
  const passcode = document.getElementById('decrypt-passcode').value
  const statusEl = document.getElementById('decrypt-status')
  const btn      = document.getElementById('decrypt-btn')
  const fillEl   = document.getElementById('decrypt-progress-fill')
  const barEl    = document.getElementById('decrypt-progress')

  clearStatus(statusEl)
  if (!file)     { setStatus(statusEl, 'error', 'Select a .cnsl file to decrypt.'); return }
  if (!passcode) { setStatus(statusEl, 'error', 'Enter the passcode.'); return }

  btn.disabled = true
  btn.textContent = 'Decrypting…'
  setProgress(fillEl, barEl, 20)

  try {
    const buffer = await file.arrayBuffer()
    setProgress(fillEl, barEl, 40)
    const { filename, salt, iv, wrappedKey, ciphertext } = unpackCnsl(buffer)
    setProgress(fillEl, barEl, 60)
    const plaintext = await conseal.unsealEnvelope({ ciphertext, iv, wrappedKey, salt }, passcode)
    setProgress(fillEl, barEl, 95)
    downloadBuffer(plaintext, filename)
    setProgress(fillEl, barEl, 100)
    setStatus(statusEl, 'ok', `Decrypted → ${filename} downloaded.`)
  } catch (err) {
    if (err.name === 'OperationError') {
      setStatus(statusEl, 'error', 'Wrong passcode or corrupted file.')
    } else {
      setStatus(statusEl, 'error', `Error: ${err.message}`)
    }
  } finally {
    btn.disabled = false
    btn.textContent = 'Decrypt & Download →'
    setTimeout(() => setProgress(fillEl, barEl, null), 800)
  }
})

// ═══════════════════════════════════════════════════════════════════════
// TAB: ACCOUNT
// ═══════════════════════════════════════════════════════════════════════

let acctAek = null
let acctMnemonic = ''
let acctSealedPayload = null

document.getElementById('setup-btn').addEventListener('click', async () => {
  const passphrase = document.getElementById('setup-pass').value
  const statusEl   = document.getElementById('setup-status')
  const btn        = document.getElementById('setup-btn')

  clearStatus(statusEl)
  if (!passphrase) { setStatus(statusEl, 'error', 'Enter a passphrase.'); return }

  btn.disabled = true
  btn.textContent = 'Creating…'

  try {
    const mnemonic = conseal.generateMnemonic()
    acctMnemonic = mnemonic
    const entropy = mnemonicToEntropy(mnemonic, wordlist)
    acctAek = await conseal.importAesKey(entropy, true)
    const { wrappedKey, salt } = await conseal.wrapKey(passphrase, acctAek)

    document.getElementById('mnemonic-display').value = mnemonic
    document.getElementById('wrapped-display').value = JSON.stringify({
      wrappedKey: conseal.toBase64(wrappedKey),
      salt: conseal.toBase64(salt),
    }, null, 2)

    document.getElementById('setup-result').style.display = 'flex'
    document.getElementById('fill-mnemonic').style.display = 'block'
    document.getElementById('num-1').classList.add('done')
    document.getElementById('card-seal-acct').classList.remove('dim')
    document.getElementById('num-2').classList.add('done')
    setStatus(statusEl, 'ok', 'Account key created. Save your mnemonic before continuing.')
  } catch (err) {
    setStatus(statusEl, 'error', `Error: ${err.message}`)
  } finally {
    btn.disabled = false
    btn.textContent = 'Create →'
  }
})

document.getElementById('copy-mnemonic').addEventListener('click', () => {
  const mnemonic = document.getElementById('mnemonic-display').value
  navigator.clipboard.writeText(mnemonic).then(() => {
    const btn = document.getElementById('copy-mnemonic')
    btn.textContent = 'Copied!'
    setTimeout(() => btn.textContent = 'Copy', 1500)
  })
})

document.getElementById('seal-acct-btn').addEventListener('click', async () => {
  const text     = document.getElementById('seal-text').value
  const statusEl = document.getElementById('seal-acct-status')
  const btn      = document.getElementById('seal-acct-btn')

  clearStatus(statusEl)
  if (!text.trim()) { setStatus(statusEl, 'error', 'Enter a message to seal.'); return }
  if (!acctAek)     { setStatus(statusEl, 'error', 'Create an account first.'); return }

  btn.disabled = true
  btn.textContent = 'Sealing…'

  try {
    acctSealedPayload = await conseal.seal(acctAek, new TextEncoder().encode(text).buffer)
    document.getElementById('seal-acct-output').value = JSON.stringify({
      ciphertext: conseal.toBase64(acctSealedPayload.ciphertext),
      iv:         conseal.toBase64(acctSealedPayload.iv),
    }, null, 2)
    document.getElementById('seal-result').style.display = 'flex'
    document.getElementById('card-recover').classList.remove('dim')
    document.getElementById('num-3').classList.add('done')
    setStatus(statusEl, 'ok', 'Message sealed. Now try recovering from your mnemonic.')
  } catch (err) {
    setStatus(statusEl, 'error', `Error: ${err.message}`)
  } finally {
    btn.disabled = false
    btn.textContent = 'Seal →'
  }
})

document.getElementById('fill-mnemonic').addEventListener('click', () => {
  document.getElementById('recover-mnemonic').value = acctMnemonic
})

document.getElementById('recover-btn').addEventListener('click', async () => {
  const mnemonic = document.getElementById('recover-mnemonic').value.trim().replace(/\s+/g, ' ')
  const statusEl = document.getElementById('recover-status')
  const btn      = document.getElementById('recover-btn')

  clearStatus(statusEl)
  if (!mnemonic)          { setStatus(statusEl, 'error', 'Enter your recovery mnemonic.'); return }
  if (!acctSealedPayload) { setStatus(statusEl, 'error', 'Seal a message first (step 2).'); return }

  btn.disabled = true
  btn.textContent = 'Recovering…'

  try {
    const recoveredAek = await conseal.recoverWithMnemonic(mnemonic)
    const plaintext = new TextDecoder().decode(
      await conseal.unseal(recoveredAek, acctSealedPayload.ciphertext, acctSealedPayload.iv)
    )
    document.getElementById('recover-output').value = plaintext
    document.getElementById('recover-result').style.display = 'flex'
    document.getElementById('num-3').classList.add('done')
    setStatus(statusEl, 'ok', 'Key recovered from mnemonic — message unsealed successfully.')
  } catch (err) {
    if (err.name === 'OperationError') {
      setStatus(statusEl, 'error', 'Wrong mnemonic — could not decrypt the message.')
    } else {
      setStatus(statusEl, 'error', `Error: ${err.message}`)
    }
  } finally {
    btn.disabled = false
    btn.textContent = 'Recover & Unseal →'
  }
})

// ═══════════════════════════════════════════════════════════════════════
// TAB: P2P
// ═══════════════════════════════════════════════════════════════════════

const p2pState = {
  alice: { ecdh: null, ecdsa: null },
  bob:   { ecdh: null, ecdsa: null },
  packet: null,
}

function p2pSetStatus(id, type, msg) {
  const el = document.getElementById(id)
  el.className = `status ${type}`
  el.textContent = msg
}

function p2pClearStatus(id) {
  const el = document.getElementById(id)
  el.className = 'status'
  el.textContent = ''
}

function jwkThumb(jwk) {
  return jwk.x ? `${jwk.x.slice(0, 12)}…` : '?'
}

async function generateIdentity(who) {
  const ecdh  = await conseal.generateECDHKeyPair()
  const ecdsa = await conseal.generateECDSAKeyPair()
  p2pState[who].ecdh  = ecdh
  p2pState[who].ecdsa = ecdsa

  const ecdhJwk  = await conseal.exportPublicKeyAsJwk(ecdh.publicKey)
  const ecdsaJwk = await conseal.exportPublicKeyAsJwk(ecdsa.publicKey)

  document.getElementById(`${who}-ecdh-thumb`).textContent  = jwkThumb(ecdhJwk)
  document.getElementById(`${who}-ecdsa-thumb`).textContent = jwkThumb(ecdsaJwk)
  document.getElementById(`${who}-keys-display`).style.display = 'flex'

  p2pSetStatus(`${who}-keygen-status`, 'ok', 'ECDH + ECDSA key pairs generated.')
  p2pCheckReady()
}

function p2pCheckReady() {
  const bothReady = p2pState.alice.ecdh && p2pState.bob.ecdh
  document.getElementById('alice-message').disabled = !bothReady
  document.getElementById('alice-send').disabled    = !bothReady
}

document.getElementById('alice-keygen').addEventListener('click', () => generateIdentity('alice'))
document.getElementById('bob-keygen').addEventListener('click',   () => generateIdentity('bob'))

document.getElementById('alice-send').addEventListener('click', async () => {
  const text = document.getElementById('alice-message').value.trim()
  if (!text) { p2pSetStatus('alice-send-status', 'error', 'Enter a message first.'); return }

  p2pClearStatus('alice-send-status')
  const btn = document.getElementById('alice-send')
  btn.disabled = true
  btn.textContent = 'Sealing…'

  try {
    const plaintext = new TextEncoder().encode(text)
    const { ciphertext, iv, ephemeralPublicKey } = await conseal.sealMessage(
      p2pState.bob.ecdh.publicKey,
      plaintext.buffer
    )
    const signature = await conseal.sign(p2pState.alice.ecdsa.privateKey, ciphertext)
    p2pState.packet = { ciphertext, iv, ephemeralPublicKey, signature, tampered: false }

    document.getElementById('pkt-ciphertext').textContent = conseal.toBase64(ciphertext).slice(0, 32) + '…'
    document.getElementById('pkt-iv').textContent         = conseal.toBase64(iv)
    document.getElementById('pkt-ephem').textContent      = ephemeralPublicKey.x?.slice(0, 20) + '…'
    document.getElementById('pkt-sig').textContent        = conseal.toBase64(signature).slice(0, 32) + '…'
    document.getElementById('packet-display').classList.add('visible')
    document.getElementById('no-packet').style.display = 'none'
    document.getElementById('bob-unseal').disabled  = false
    document.getElementById('tamper-btn').disabled  = false
    document.getElementById('tamper-btn').textContent = 'Tamper signature'
    document.getElementById('p2p-verify-result').className = 'verify-result'
    document.getElementById('bob-received').value = ''
    p2pClearStatus('bob-unseal-status')

    p2pSetStatus('alice-send-status', 'ok', "Message sealed with Bob's public key and signed with Alice's private key.")
  } catch (err) {
    p2pSetStatus('alice-send-status', 'error', `Error: ${err.message}`)
  } finally {
    btn.disabled = false
    btn.textContent = 'Seal & Sign →'
  }
})

document.getElementById('tamper-btn').addEventListener('click', () => {
  if (!p2pState.packet) return
  const tampered = p2pState.packet.signature.slice(0)
  new Uint8Array(tampered)[0] ^= 0xff
  p2pState.packet.signature = tampered
  p2pState.packet.tampered  = true
  document.getElementById('pkt-sig').textContent = conseal.toBase64(tampered).slice(0, 32) + '… ⚠︎ tampered'
  document.getElementById('tamper-btn').textContent = 'Signature tampered'
  document.getElementById('tamper-btn').disabled = true
  document.getElementById('p2p-verify-result').className = 'verify-result'
  document.getElementById('bob-received').value = ''
  p2pClearStatus('bob-unseal-status')
})

document.getElementById('bob-unseal').addEventListener('click', async () => {
  if (!p2pState.packet) return

  p2pClearStatus('bob-unseal-status')
  document.getElementById('bob-received').value = ''
  document.getElementById('p2p-verify-result').className = 'verify-result'

  const btn = document.getElementById('bob-unseal')
  btn.disabled = true
  btn.textContent = 'Verifying…'

  try {
    const { ciphertext, iv, ephemeralPublicKey, signature } = p2pState.packet
    const valid = await conseal.verify(p2pState.alice.ecdsa.publicKey, signature, ciphertext)

    const verifyEl = document.getElementById('p2p-verify-result')
    verifyEl.classList.add('visible')

    if (!valid) {
      verifyEl.className = 'verify-result visible invalid'
      verifyEl.querySelector('.icon').textContent  = '✗'
      verifyEl.querySelector('.label').textContent = 'Signature invalid — message rejected'
      p2pSetStatus('bob-unseal-status', 'error', 'Signature verification failed. The message was tampered with or did not come from Alice.')
      return
    }

    verifyEl.className = 'verify-result visible valid'
    verifyEl.querySelector('.icon').textContent  = '✓'
    verifyEl.querySelector('.label').textContent = 'Signature valid — confirmed from Alice'

    btn.textContent = 'Unsealing…'
    const plaintext = await conseal.unsealMessage(
      p2pState.bob.ecdh.privateKey,
      ciphertext, iv, ephemeralPublicKey
    )
    document.getElementById('bob-received').value = new TextDecoder().decode(plaintext)
    p2pSetStatus('bob-unseal-status', 'ok', 'Signature verified ✓  —  message decrypted.')
  } catch (err) {
    p2pSetStatus('bob-unseal-status', 'error', `Error: ${err.message}`)
  } finally {
    btn.disabled = false
    btn.textContent = 'Verify & Unseal'
  }
})

// ═══════════════════════════════════════════════════════════════════════
// TAB: SIGN
// ═══════════════════════════════════════════════════════════════════════

const signState = {
  privateKey: null,
  publicKey:  null,
  originalDoc: '',
  currentDoc: '',
  originalSig: null,
  currentSig: null,
  tamperedDoc: false,
  tamperedSig: false,
}

function signSetStatus(id, type, msg) {
  const el = document.getElementById(id)
  el.className = `status ${type}`
  el.textContent = msg
}

function signClearStatus(id) {
  const el = document.getElementById(id)
  el.className = 'status'
  el.textContent = ''
}

function resetSigning() {
  document.getElementById('sig-box').classList.remove('visible')
  document.getElementById('sign-tamper-card').style.display = 'none'
  document.getElementById('sign-verify-card').style.display = 'none'
  document.getElementById('sign-verify-banner').className = 'verify-banner'
  signClearStatus('sign-status')
  signClearStatus('tamper-status')
}

async function doKeygen() {
  const btn = document.getElementById('sign-keygen-btn')
  btn.disabled = true
  btn.textContent = 'Generating…'
  signClearStatus('sign-keygen-status')

  try {
    const { publicKey, privateKey } = await conseal.generateECDSAKeyPair()
    signState.publicKey  = publicKey
    signState.privateKey = privateKey

    const jwk = await conseal.exportPublicKeyAsJwk(publicKey)
    document.getElementById('sign-pub-thumb').textContent = `${jwk.x?.slice(0, 22)}… (x-coordinate, P-256)`

    document.getElementById('sign-keypair-box').classList.add('visible')
    document.getElementById('sign-keygen-again-btn').style.display = 'inline-block'
    document.getElementById('sign-document').disabled = false
    document.getElementById('sign-btn').disabled = false

    signSetStatus('sign-keygen-status', 'ok', 'ECDSA P-256 key pair generated.')
    resetSigning()
  } catch (err) {
    signSetStatus('sign-keygen-status', 'error', `Error: ${err.message}`)
  } finally {
    btn.disabled = false
    btn.textContent = 'Generate key pair'
  }
}

document.getElementById('sign-keygen-btn').addEventListener('click', doKeygen)
document.getElementById('sign-keygen-again-btn').addEventListener('click', doKeygen)

document.getElementById('sign-btn').addEventListener('click', async () => {
  const text = document.getElementById('sign-document').value
  if (!text.trim()) { signSetStatus('sign-status', 'error', 'Enter a document to sign.'); return }

  const btn = document.getElementById('sign-btn')
  btn.disabled = true
  btn.textContent = 'Signing…'
  signClearStatus('sign-status')

  try {
    const encoded = new TextEncoder().encode(text)
    const sig = await conseal.sign(signState.privateKey, encoded.buffer)

    signState.originalDoc = text
    signState.currentDoc  = text
    signState.originalSig = sig
    signState.currentSig  = sig
    signState.tamperedDoc = false
    signState.tamperedSig = false

    document.getElementById('sig-hash').textContent = `SHA-256 of ${encoded.byteLength} bytes`
    document.getElementById('sig-val').textContent  = conseal.toBase64(sig).slice(0, 48) + '…'
    document.getElementById('sig-box').classList.add('visible')
    document.getElementById('sign-tamper-card').style.display = 'block'
    document.getElementById('sign-verify-card').style.display = 'block'
    document.getElementById('sign-restore-btn').style.display = 'none'
    document.getElementById('tamper-doc-btn').disabled = false
    document.getElementById('tamper-sig-btn').disabled = false
    document.getElementById('sign-verify-banner').className = 'verify-banner'
    signClearStatus('tamper-status')
    signSetStatus('sign-status', 'ok', 'Document signed with private key.')
  } catch (err) {
    signSetStatus('sign-status', 'error', `Error: ${err.message}`)
  } finally {
    btn.disabled = false
    btn.textContent = 'Sign →'
  }
})

document.getElementById('tamper-doc-btn').addEventListener('click', () => {
  if (signState.tamperedDoc) return
  const tampered = signState.originalDoc + ' '
  signState.currentDoc  = tampered
  signState.tamperedDoc = true
  document.getElementById('sign-document').value = tampered
  document.getElementById('tamper-doc-btn').disabled = true
  document.getElementById('sign-restore-btn').style.display = 'inline-block'
  document.getElementById('sign-verify-banner').className = 'verify-banner'
  signSetStatus('tamper-status', 'error', 'Document tampered — a trailing space was appended. The signature no longer matches.')
})

document.getElementById('tamper-sig-btn').addEventListener('click', () => {
  if (signState.tamperedSig) return
  const tampered = signState.originalSig.slice(0)
  new Uint8Array(tampered)[0] ^= 0xff
  signState.currentSig  = tampered
  signState.tamperedSig = true
  document.getElementById('sig-val').textContent = conseal.toBase64(tampered).slice(0, 48) + '… ⚠︎ tampered'
  document.getElementById('tamper-sig-btn').disabled = true
  document.getElementById('sign-restore-btn').style.display = 'inline-block'
  document.getElementById('sign-verify-banner').className = 'verify-banner'
  signSetStatus('tamper-status', 'error', 'Signature tampered — first byte flipped. Verification will fail.')
})

document.getElementById('sign-restore-btn').addEventListener('click', () => {
  signState.currentDoc  = signState.originalDoc
  signState.currentSig  = signState.originalSig
  signState.tamperedDoc = false
  signState.tamperedSig = false
  document.getElementById('sign-document').value = signState.originalDoc
  document.getElementById('sig-val').textContent = conseal.toBase64(signState.originalSig).slice(0, 48) + '…'
  document.getElementById('tamper-doc-btn').disabled = false
  document.getElementById('tamper-sig-btn').disabled = false
  document.getElementById('sign-restore-btn').style.display = 'none'
  document.getElementById('sign-verify-banner').className = 'verify-banner'
  signClearStatus('tamper-status')
})

document.getElementById('sign-verify-btn').addEventListener('click', async () => {
  const btn = document.getElementById('sign-verify-btn')
  btn.disabled = true
  btn.textContent = 'Verifying…'

  try {
    const encoded = new TextEncoder().encode(signState.currentDoc)
    const valid = await conseal.verify(signState.publicKey, signState.currentSig, encoded.buffer)
    const banner = document.getElementById('sign-verify-banner')

    if (valid) {
      banner.className = 'verify-banner visible valid'
      document.getElementById('sign-verify-icon').textContent     = '✓'
      document.getElementById('sign-verify-headline').textContent = 'Signature valid'
      document.getElementById('sign-verify-detail').textContent   =
        'The document has not been modified since it was signed. The signature was produced by the private key that corresponds to this public key.'
    } else {
      banner.className = 'verify-banner visible invalid'
      document.getElementById('sign-verify-icon').textContent     = '✗'
      document.getElementById('sign-verify-headline').textContent = 'Signature invalid'
      const reason = signState.tamperedDoc && signState.tamperedSig
        ? 'Both the document and signature were tampered.'
        : signState.tamperedDoc
        ? 'The document was modified after signing — even a single character change breaks the signature.'
        : signState.tamperedSig
        ? 'The signature was altered — any modification to the signature bytes causes verification to fail.'
        : 'Verification failed. The document or signature does not match the key.'
      document.getElementById('sign-verify-detail').textContent = reason
    }
  } catch (err) {
    const banner = document.getElementById('sign-verify-banner')
    banner.className = 'verify-banner visible invalid'
    document.getElementById('sign-verify-icon').textContent     = '✗'
    document.getElementById('sign-verify-headline').textContent = 'Verification error'
    document.getElementById('sign-verify-detail').textContent   = err.message
  } finally {
    btn.disabled = false
    btn.textContent = 'Verify →'
  }
})

// ═══════════════════════════════════════════════════════════════════════
// TAB: REKEY
// ═══════════════════════════════════════════════════════════════════════

let rekeyState = {
  wrappedKey: null,
  salt: null,
  sealed: null,
  newPass: null,
}

function rekeySetStatus(el, type, msg) { el.className = `status ${type}`; el.textContent = msg }
function rekeyClearStatus(el) { el.className = 'status'; el.textContent = '' }
function encodeBlob({ wrappedKey, salt }) {
  return JSON.stringify({ wrappedKey: conseal.toBase64(wrappedKey), salt: conseal.toBase64(salt) }, null, 2)
}

document.getElementById('rekey-setup-btn').addEventListener('click', async () => {
  const passphrase = document.getElementById('rekey-setup-pass').value
  const message    = document.getElementById('rekey-setup-msg').value
  const statusEl   = document.getElementById('rekey-setup-status')
  const btn        = document.getElementById('rekey-setup-btn')

  rekeyClearStatus(statusEl)
  if (!passphrase)     { rekeySetStatus(statusEl, 'error', 'Enter a passphrase.'); return }
  if (!message.trim()) { rekeySetStatus(statusEl, 'error', 'Enter a message to seal.'); return }

  btn.disabled = true; btn.textContent = 'Creating… (slow by design)'

  try {
    const aek = await conseal.generateAesKey(true)
    const blob = await conseal.wrapKey(passphrase, aek)
    rekeyState.wrappedKey = blob.wrappedKey
    rekeyState.salt = blob.salt
    rekeyState.sealed = await conseal.seal(aek, new TextEncoder().encode(message).buffer)

    const blobStr = encodeBlob(blob)
    document.getElementById('rekey-blob-before').value = blobStr
    document.getElementById('rekey-compare-before').value = blobStr
    document.getElementById('rekey-sealed-msg').value = JSON.stringify({
      ciphertext: conseal.toBase64(rekeyState.sealed.ciphertext),
      iv: conseal.toBase64(rekeyState.sealed.iv),
    }, null, 2)
    document.getElementById('rekey-old-pass').value = passphrase

    document.getElementById('rekey-setup-result').style.display = 'flex'
    document.getElementById('rekey-num-1').classList.add('done')
    document.getElementById('rekey-card-rekey').classList.remove('dim')
    rekeySetStatus(statusEl, 'ok', 'Account key created and message sealed.')
  } catch (err) {
    rekeySetStatus(statusEl, 'error', `Error: ${err.message}`)
  } finally {
    btn.disabled = false; btn.textContent = 'Create & Seal →'
  }
})

document.getElementById('rekey-btn').addEventListener('click', async () => {
  const oldPass  = document.getElementById('rekey-old-pass').value
  const newPass  = document.getElementById('rekey-new-pass').value
  const statusEl = document.getElementById('rekey-status')
  const btn      = document.getElementById('rekey-btn')

  rekeyClearStatus(statusEl)
  if (!oldPass) { rekeySetStatus(statusEl, 'error', 'Enter the old passphrase.'); return }
  if (!newPass) { rekeySetStatus(statusEl, 'error', 'Enter a new passphrase.'); return }
  if (oldPass === newPass) { rekeySetStatus(statusEl, 'error', 'New passphrase must differ from the old one.'); return }

  btn.disabled = true; btn.textContent = 'Rekeying… (slow by design)'

  try {
    const result = await conseal.rekey(oldPass, newPass, rekeyState.wrappedKey, rekeyState.salt)
    rekeyState.wrappedKey = result.wrappedKey
    rekeyState.salt = result.salt
    rekeyState.newPass = newPass

    document.getElementById('rekey-compare-after').value = encodeBlob(result)
    document.getElementById('rekey-result').style.display = 'flex'
    document.getElementById('rekey-num-2').classList.add('done')
    document.getElementById('rekey-card-verify').classList.remove('dim')
    rekeySetStatus(statusEl, 'ok', 'Rekeyed. The wrapped blob has new bytes — same AEK inside.')
  } catch (err) {
    if (err.name === 'OperationError') {
      rekeySetStatus(statusEl, 'error', 'Wrong old passphrase.')
    } else {
      rekeySetStatus(statusEl, 'error', `Error: ${err.message}`)
    }
  } finally {
    btn.disabled = false; btn.textContent = 'Rekey →'
  }
})

document.getElementById('rekey-verify-btn').addEventListener('click', async () => {
  const statusEl = document.getElementById('rekey-verify-status')
  const btn      = document.getElementById('rekey-verify-btn')

  rekeyClearStatus(statusEl)
  btn.disabled = true; btn.textContent = 'Unsealing… (slow by design)'

  try {
    const aek = await conseal.unwrapKey(rekeyState.newPass, rekeyState.wrappedKey, rekeyState.salt)
    const plaintext = new TextDecoder().decode(
      await conseal.unseal(aek, rekeyState.sealed.ciphertext, rekeyState.sealed.iv)
    )
    document.getElementById('rekey-verify-output').value = plaintext
    document.getElementById('rekey-verify-result').style.display = 'flex'
    document.getElementById('rekey-num-3').classList.add('done')
    rekeySetStatus(statusEl, 'ok', 'Unsealed with the new passphrase — content encrypted before the rekey is still accessible.')
  } catch (err) {
    rekeySetStatus(statusEl, 'error', `Error: ${err.message}`)
  } finally {
    btn.disabled = false; btn.textContent = 'Unseal →'
  }
})

// ═══════════════════════════════════════════════════════════════════════
// TAB: SECRET KEY
// ═══════════════════════════════════════════════════════════════════════

let skState = {
  passphrase:  null,
  secretKey:   null,
  wrappedKey:  null,
  salt:        null,
  sealed:      null,
}

function skSetStatus(el, type, msg) { el.className = `status ${type}`; el.textContent = msg }
function skClearStatus(el) { el.className = 'status'; el.textContent = '' }

document.getElementById('sk-setup-btn').addEventListener('click', async () => {
  const passphrase = document.getElementById('sk-passphrase').value
  const message    = document.getElementById('sk-message').value
  const statusEl   = document.getElementById('sk-setup-status')
  const btn        = document.getElementById('sk-setup-btn')

  skClearStatus(statusEl)
  if (!passphrase)     { skSetStatus(statusEl, 'error', 'Enter a passphrase.'); return }
  if (!message.trim()) { skSetStatus(statusEl, 'error', 'Enter a message to seal.'); return }

  btn.disabled = true; btn.textContent = 'Generating… (slow by design)'

  try {
    const aek = await conseal.generateAesKey(true)
    const sk  = conseal.generateSecretKey()
    const { wrappedKey, salt } = await conseal.wrapKey(passphrase, aek, sk)
    const sealed = await conseal.seal(aek, new TextEncoder().encode(message).buffer)

    skState = { passphrase, secretKey: sk, wrappedKey, salt, sealed }

    document.getElementById('sk-key-display').value = conseal.toBase64(sk)
    document.getElementById('sk-blob-display').value = JSON.stringify(
      { wrappedKey: conseal.toBase64(wrappedKey), salt: conseal.toBase64(salt) }, null, 2
    )
    document.getElementById('sk-sealed-display').value = JSON.stringify(
      { ciphertext: conseal.toBase64(sealed.ciphertext), iv: conseal.toBase64(sealed.iv) }, null, 2
    )

    document.getElementById('sk-setup-result').style.display = 'flex'
    document.getElementById('sk-num-1').classList.add('done')
    document.getElementById('sk-card-unlock').classList.remove('dim')
    skSetStatus(statusEl, 'ok', 'AEK wrapped with passphrase + Secret Key.')
  } catch (err) {
    skSetStatus(statusEl, 'error', `Error: ${err.message}`)
  } finally {
    btn.disabled = false; btn.textContent = 'Generate Secret Key & Wrap →'
  }
})

document.getElementById('sk-unlock-btn').addEventListener('click', async () => {
  const statusEl = document.getElementById('sk-unlock-status')
  const btn      = document.getElementById('sk-unlock-btn')

  skClearStatus(statusEl)
  btn.disabled = true; btn.textContent = 'Unlocking… (slow by design)'

  try {
    const aek = await conseal.unwrapKey(
      skState.passphrase, skState.wrappedKey, skState.salt, skState.secretKey
    )
    const plaintext = new TextDecoder().decode(
      await conseal.unseal(aek, skState.sealed.ciphertext, skState.sealed.iv)
    )

    document.getElementById('sk-unlock-output').value = plaintext
    document.getElementById('sk-unlock-result').style.display = 'flex'
    document.getElementById('sk-num-2').classList.add('done')
    document.getElementById('sk-card-attack').classList.remove('dim')
    skSetStatus(statusEl, 'ok', '✓ Decrypted — correct passphrase + Secret Key.')
  } catch (err) {
    skSetStatus(statusEl, 'error', `Error: ${err.message}`)
  } finally {
    btn.disabled = false; btn.textContent = 'Unlock & Decrypt →'
  }
})

document.getElementById('sk-attack-btn').addEventListener('click', async () => {
  const statusEl = document.getElementById('sk-attack-status')
  const btn      = document.getElementById('sk-attack-btn')

  skClearStatus(statusEl)
  btn.disabled = true; btn.textContent = 'Attempting… (slow by design)'

  try {
    const wrongSk = conseal.generateSecretKey()
    await conseal.unwrapKey(skState.passphrase, skState.wrappedKey, skState.salt, wrongSk)
    skSetStatus(statusEl, 'error', 'Unexpected: unwrap succeeded with wrong Secret Key.')
  } catch {
    document.getElementById('sk-num-3').classList.add('done')
    skSetStatus(statusEl, 'ok', '✓ Correctly rejected — correct passphrase, wrong Secret Key. The passphrase alone is not enough.')
  } finally {
    btn.disabled = false; btn.textContent = 'Try Wrong Secret Key →'
  }
})

// ═══════════════════════════════════════════════════════════════════════
// TAB: JWK
// ═══════════════════════════════════════════════════════════════════════

function toHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
}

function formatFingerprint(hex) {
  return hex.match(/.{1,4}/g).join(' ').toUpperCase()
}

function decodeCoord(b64url) {
  try {
    const bytes = conseal.fromBase64Url(b64url)
    return `${toHex(bytes)}  (${bytes.byteLength} bytes)`
  } catch {
    return b64url
  }
}

const JWK_FIELD_DOCS = {
  kty:     { label: 'Key type',       desc: v => v === 'EC' ? 'Elliptic Curve' : v },
  crv:     { label: 'Curve',          desc: v => v },
  x:       { label: 'Public point X', desc: decodeCoord },
  y:       { label: 'Public point Y', desc: decodeCoord },
  use:     { label: 'Intended use',   desc: v => v === 'sig' ? 'sig — digital signatures' : v === 'enc' ? 'enc — encryption / key agreement' : v },
  key_ops: { label: 'Key ops',        desc: v => Array.isArray(v) ? v.join(', ') : v },
  alg:     { label: 'Algorithm',      desc: v => v },
  kid:     { label: 'Key ID',         desc: v => v },
  ext:     { label: 'Extractable',    desc: v => String(v) },
}

function renderJwkFields(jwk) {
  const table = document.getElementById('jwk-fields-table')
  table.innerHTML = ''
  const order = ['kty', 'crv', 'use', 'alg', 'key_ops', 'kid', 'ext', 'x', 'y']
  const keys = [...new Set([...order, ...Object.keys(jwk)])]
  for (const k of keys) {
    if (!(k in jwk)) continue
    const row = document.createElement('div')
    row.className = 'field-row'
    const keyEl = document.createElement('div')
    keyEl.className = 'field-key'
    keyEl.textContent = JWK_FIELD_DOCS[k]?.label ?? k
    const valEl = document.createElement('div')
    valEl.className = 'field-val'
    valEl.textContent = JWK_FIELD_DOCS[k]?.desc ? JWK_FIELD_DOCS[k].desc(jwk[k]) : String(jwk[k])
    if (k === 'crv' || k === 'use' || k === 'alg') valEl.classList.add('highlight')
    if (k === 'x' || k === 'y') valEl.classList.add('muted')
    row.appendChild(keyEl)
    row.appendChild(valEl)
    table.appendChild(row)
  }
}

async function deriveFingerprint(jwk) {
  const x = conseal.fromBase64Url(jwk.x)
  const y = conseal.fromBase64Url(jwk.y)
  const point = new Uint8Array(1 + x.byteLength + y.byteLength)
  point[0] = 0x04
  point.set(x, 1)
  point.set(y, 1 + x.byteLength)
  return toHex(await conseal.digest(point))
}

async function importAndInspect(jwkStr) {
  const jwk = JSON.parse(jwkStr)
  if (jwk.kty !== 'EC')  throw new Error(`Expected kty "EC", got "${jwk.kty}"`)
  if (!jwk.crv)          throw new Error('Missing "crv" field')
  if (!jwk.x || !jwk.y) throw new Error('Missing public point coordinates (x, y)')
  if (jwk.d)             throw new Error('This looks like a private key — only paste public keys here')
  let algorithm = 'ECDH'
  if (jwk.use === 'sig' || (jwk.key_ops && jwk.key_ops.includes('verify'))) algorithm = 'ECDSA'
  await conseal.importPublicKeyFromJwk(jwk, algorithm)
  return jwk
}

async function jwkGenerateAndShow(algorithm) {
  const pair = algorithm === 'ECDH'
    ? await conseal.generateECDHKeyPair()
    : await conseal.generateECDSAKeyPair()
  const jwk = await conseal.exportPublicKeyAsJwk(pair.publicKey)
  if (algorithm === 'ECDH')  jwk.use = 'enc'
  if (algorithm === 'ECDSA') jwk.use = 'sig'
  document.getElementById('jwk-input').value = JSON.stringify(jwk, null, 2)
}

document.getElementById('jwk-gen-ecdh').addEventListener('click', async () => {
  document.getElementById('jwk-gen-ecdh').disabled = true
  try { await jwkGenerateAndShow('ECDH') } finally { document.getElementById('jwk-gen-ecdh').disabled = false }
})

document.getElementById('jwk-gen-ecdsa').addEventListener('click', async () => {
  document.getElementById('jwk-gen-ecdsa').disabled = true
  try { await jwkGenerateAndShow('ECDSA') } finally { document.getElementById('jwk-gen-ecdsa').disabled = false }
})

document.getElementById('jwk-clear-btn').addEventListener('click', () => {
  document.getElementById('jwk-input').value = ''
  document.getElementById('jwk-result-card').style.display = 'none'
  const s = document.getElementById('jwk-inspect-status')
  s.className = 'status'; s.textContent = ''
})

document.getElementById('jwk-inspect-btn').addEventListener('click', async () => {
  const input    = document.getElementById('jwk-input').value.trim()
  const statusEl = document.getElementById('jwk-inspect-status')
  const btn      = document.getElementById('jwk-inspect-btn')

  statusEl.className = 'status'; statusEl.textContent = ''
  document.getElementById('jwk-result-card').style.display = 'none'

  if (!input) { statusEl.className = 'status error'; statusEl.textContent = 'Paste a JWK or generate one above.'; return }

  btn.disabled = true; btn.textContent = 'Inspecting…'

  try {
    const jwk = await importAndInspect(input)
    renderJwkFields(jwk)
    document.getElementById('jwk-fingerprint').textContent = formatFingerprint(await deriveFingerprint(jwk))
    document.getElementById('jwk-result-card').style.display = 'flex'
    statusEl.className = 'status ok'
    statusEl.textContent = 'Valid key — point confirmed on curve.'
  } catch (err) {
    statusEl.className = 'status error'
    if (err instanceof SyntaxError) {
      statusEl.textContent = 'Invalid JSON.'
    } else if (err.name === 'DataError') {
      statusEl.textContent = 'Invalid key — point is not on the specified curve.'
    } else {
      statusEl.textContent = `Error: ${err.message}`
    }
  } finally {
    btn.disabled = false; btn.textContent = 'Inspect →'
  }
})
