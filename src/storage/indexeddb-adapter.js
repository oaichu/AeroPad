export const VAULT_DB_NAME = 'aeropad-vault';
export const VAULT_DB_VERSION = 1;
export const VAULT_STORE_NAME = 'vault';
export const CURRENT_KEY = 'current';

function asError(value, fallback) {
  if (value instanceof Error) return value;
  const error = new Error(value?.message || fallback);
  error.code = 'indexeddb_error';
  return error;
}

export class IndexedDBVaultAdapter {
  constructor({ indexedDB = globalThis.indexedDB, databaseName = VAULT_DB_NAME, version = VAULT_DB_VERSION } = {}) {
    if (!indexedDB || typeof indexedDB.open !== 'function') throw new TypeError('IndexedDB is unavailable');
    this.indexedDB = indexedDB;
    this.databaseName = databaseName;
    this.version = version;
    this.dbPromise = null;
  }

  open() {
    if (this.dbPromise) return this.dbPromise;
    this.dbPromise = new Promise((resolve, reject) => {
      let request;
      try {
        request = this.indexedDB.open(this.databaseName, this.version);
        request.onupgradeneeded = event => {
          const db = event.target.result;
          if (!db.objectStoreNames.contains(VAULT_STORE_NAME)) db.createObjectStore(VAULT_STORE_NAME, { keyPath: 'id' });
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(asError(request.error, 'Unable to open vault database'));
        request.onblocked = () => reject(asError(null, 'Vault database upgrade is blocked'));
      } catch (error) {
        reject(asError(error, 'Unable to open vault database'));
      }
    });
    this.dbPromise.catch(() => { this.dbPromise = null; });
    return this.dbPromise;
  }

  async getCurrent() {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let value = null;
      let settled = false;
      const fail = error => { if (!settled) { settled = true; reject(asError(error, 'Unable to read vault')); } };
      try {
        const tx = db.transaction(VAULT_STORE_NAME, 'readonly');
        tx.onerror = () => fail(tx.error);
        tx.onabort = () => fail(tx.error);
        tx.oncomplete = () => { if (!settled) { settled = true; resolve(value); } };
        const request = tx.objectStore(VAULT_STORE_NAME).get(CURRENT_KEY);
        request.onsuccess = () => { value = request.result ?? null; };
        request.onerror = () => fail(request.error);
      } catch (error) {
        fail(error);
      }
    });
  }

  async putCurrent(record) {
    if (!record || record.id !== CURRENT_KEY) throw asError(null, 'Only the current vault record may be written');
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = error => { if (!settled) { settled = true; reject(asError(error, 'Unable to commit vault')); } };
      try {
        const tx = db.transaction(VAULT_STORE_NAME, 'readwrite');
        tx.onerror = () => fail(tx.error);
        tx.onabort = () => fail(tx.error);
        tx.oncomplete = () => { if (!settled) { settled = true; resolve(); } };
        const request = tx.objectStore(VAULT_STORE_NAME).put(record);
        request.onerror = () => fail(request.error);
      } catch (error) {
        fail(error);
      }
    });
  }
}
