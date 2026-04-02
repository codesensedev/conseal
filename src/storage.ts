/**
 * IndexedDB persistence for CryptoKey objects.
 *
 * Keeps non-extractable CryptoKey objects available across page refreshes
 * without ever exposing key bytes to JavaScript. CryptoKey objects are
 * structured-cloneable and can be stored in IndexedDB directly.
 *
 * Database:     'conseal-keys'
 * Object store: 'keys'
 *
 * Security note: non-extractable keys cannot have their bytes read, but
 * same-origin JavaScript (including XSS) can load and use them. Preventing
 * XSS is the responsibility of the application, not this module.
 */

const DB_NAME = 'conseal-keys'
const STORE = 'keys'
const VERSION = 1

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, VERSION)
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE)
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

/** Persists a CryptoKey to IndexedDB under the given name. Overwrites if name exists. */
export async function save(name: string, key: CryptoKey): Promise<void> {
  const db = await openDb()
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite')
      tx.objectStore(STORE).put(key, name)
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error)
    })
  } finally {
    db.close()
  }
}

/** Loads a CryptoKey from IndexedDB. Returns null if the name is not found. */
export async function load(name: string): Promise<CryptoKey | null> {
  const db = await openDb()
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly')
      const req = tx.objectStore(STORE).get(name)
      let result: CryptoKey | null = null
      req.onsuccess = () => {
        result = (req.result as CryptoKey | undefined) ?? null
      }
      tx.oncomplete = () => resolve(result)
      tx.onerror = () => reject(tx.error)
    })
  } finally {
    db.close()
  }
}

/** Removes a CryptoKey from IndexedDB. No-op if the name does not exist. */
export async function remove(name: string): Promise<void> {
  const db = await openDb()
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite')
      tx.objectStore(STORE).delete(name)
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error)
    })
  } finally {
    db.close()
  }
}
