import { encryptVault } from '../crypto/vault-crypto.js';

function failure(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export class VaultStore {
  constructor({ adapter, password, encrypt = encryptVault } = {}) {
    if (!adapter || typeof adapter.getCurrent !== 'function' || typeof adapter.putCurrent !== 'function') throw new TypeError('Vault adapter is required');
    this.adapter = adapter;
    this.password = password;
    this.encrypt = encrypt;
    this.currentRecord = null;
    this.lastCommittedGeneration = 0;
    this.pendingPayload = undefined;
    this.hasPending = false;
    this.worker = null;
    this.status = { state: 'idle', generation: 0, error: null };
  }

  async loadCurrent() {
    const record = await this.adapter.getCurrent();
    if (record && (!Number.isSafeInteger(record.generation) || record.generation < 1)) throw failure('invalid_current', 'Invalid current vault record');
    this.currentRecord = record || null;
    this.lastCommittedGeneration = record?.generation ?? 0;
    this.status = { state: record ? 'committed' : 'idle', generation: this.lastCommittedGeneration, error: null };
    return this.currentRecord;
  }

  commit(payload) {
    this.pendingPayload = payload;
    this.hasPending = true;
    this.status = { state: 'pending', generation: this.lastCommittedGeneration + 1, error: null };
    if (!this.worker) this.worker = Promise.resolve().then(() => this.#drain());
    return this.worker;
  }

  async flush() {
    if (this.worker) await this.worker;
    return this.currentRecord;
  }

  getStatus() {
    return { ...this.status };
  }

  async #drain() {
    try {
      while (this.hasPending) {
        const payload = this.pendingPayload;
        this.hasPending = false;
        const generation = this.lastCommittedGeneration + 1;
        this.status = { state: 'pending', generation, error: null };
        const record = await this.encrypt(payload, this.password, { generation });
        if (!record || record.id !== 'current' || record.generation !== generation) throw failure('invalid_envelope', 'Encryption returned an invalid record');
        await this.adapter.putCurrent(record);
        this.currentRecord = record;
        this.lastCommittedGeneration = generation;
        this.status = { state: 'committed', generation, error: null };
      }
      return this.currentRecord;
    } catch (error) {
      this.hasPending = false;
      this.pendingPayload = undefined;
      this.status = { state: 'save-failed', generation: this.lastCommittedGeneration, error };
      throw error;
    } finally {
      this.worker = null;
    }
  }
}
