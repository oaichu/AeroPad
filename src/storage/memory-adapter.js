export class MemoryVaultAdapter {
  constructor(current = null, { holdWrites = false } = {}) {
    this.current = current;
    this.holdWrites = holdWrites;
    this.writes = [];
    this.pending = [];
    this.failure = null;
  }

  async getCurrent() {
    return this.current;
  }

  putCurrent(record) {
    this.writes.push(record);
    if (this.failure) {
      const error = this.failure;
      this.failure = null;
      return Promise.reject(error);
    }
    if (!this.holdWrites) {
      this.current = record;
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => this.pending.push({ record, resolve, reject }));
  }

  releaseNext(error) {
    const pending = this.pending.shift();
    if (!pending) throw new Error('No pending write');
    if (error) return pending.reject(error);
    this.current = pending.record;
    pending.resolve();
  }

  failNext(error = new Error('adapter failure')) {
    this.failure = error;
  }
}
