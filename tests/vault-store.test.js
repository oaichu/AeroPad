import test from 'node:test';
import assert from 'node:assert/strict';
import { VaultStore } from '../src/storage/vault-store.js';
import { MemoryVaultAdapter } from '../src/storage/memory-adapter.js';
import { IndexedDBVaultAdapter } from '../src/storage/indexeddb-adapter.js';

const initial = { id: 'current', generation: 4, payload: { value: 0 } };
const tick = () => new Promise(resolve => setImmediate(resolve));

function makeStore(adapter, calls = [], encrypt = async (payload, _password, { generation }) => {
  calls.push({ payload, generation });
  return { id: 'current', generation, payload };
}) {
  return new VaultStore({ adapter, password: 'test-password', encrypt });
}

function fakeIndexedDB() {
  const records = new Map();
  let hasStore = false;
  const api = { failNext: false, records, open() {
    const request = {};
    queueMicrotask(() => {
      const database = {
        objectStoreNames: { contains: () => hasStore },
        createObjectStore: () => { hasStore = true; },
        transaction: () => {
          const tx = { oncomplete: null, onerror: null, onabort: null, record: null };
          const store = {
            get: (key) => { const result = { result: undefined }; queueMicrotask(() => { result.result = records.get(key); result.onsuccess?.({ target: result }); tx.oncomplete?.(); }); return result; },
            put: (record) => { tx.record = record; const result = {}; queueMicrotask(() => { if (api.failNext) { api.failNext = false; result.error = new Error('transaction failed'); result.onerror?.({ target: result }); tx.onerror?.({ target: tx }); tx.onabort?.({ target: tx }); return; } records.set('current', tx.record); result.onsuccess?.({ target: result }); tx.oncomplete?.(); }); return result; }
          };
          tx.objectStore = () => store;
          return tx;
        }
      };
      request.result = database;
      request.onupgradeneeded?.({ target: request });
      request.onsuccess?.({ target: request });
    });
    return request;
  } };
  return api;
}

test('VaultStore - coalesces synchronous commits and flush waits for adapter completion', async () => {
  const adapter = new MemoryVaultAdapter(null, { holdWrites: true });
  const calls = [];
  const store = makeStore(adapter, calls);
  const first = store.commit({ value: 1 });
  const second = store.commit({ value: 2 });
  await tick();
  assert.deepEqual(calls, [{ payload: { value: 2 }, generation: 1 }]);
  assert.equal(adapter.writes.length, 1);
  let settled = false;
  const flushed = second.then(() => { settled = true; });
  await tick();
  assert.equal(settled, false);
  adapter.releaseNext();
  await Promise.all([first, flushed]);
  assert.deepEqual(adapter.current.payload, { value: 2 });
  assert.equal(store.getStatus().state, 'committed');
});

test('VaultStore - serializes a commit added while the previous write is pending', async () => {
  const adapter = new MemoryVaultAdapter(null, { holdWrites: true });
  const calls = [];
  const store = makeStore(adapter, calls);
  const first = store.commit({ value: 1 });
  await tick();
  const second = store.commit({ value: 2 });
  await tick();
  assert.deepEqual(calls.map(call => call.payload.value), [1]);
  adapter.releaseNext();
  await tick();
  assert.deepEqual(calls.map(call => call.payload.value), [1, 2]);
  assert.equal(adapter.writes.length, 2);
  adapter.releaseNext();
  await Promise.all([first, second]);
});

test('VaultStore - loads the current record and advances generations monotonically', async () => {
  const adapter = new MemoryVaultAdapter(initial);
  const calls = [];
  const store = makeStore(adapter, calls);
  assert.deepEqual(await store.loadCurrent(), initial);
  await store.commit({ value: 1 });
  await store.commit({ value: 2 });
  assert.deepEqual(calls.map(call => call.generation), [5, 6]);
  assert.deepEqual(adapter.writes.map(record => record.generation), [5, 6]);
  assert.equal(store.getStatus().generation, 6);
});

test('VaultStore - preserves the previous record after encryption or adapter failure', async () => {
  const adapter = new MemoryVaultAdapter(initial);
  const store = makeStore(adapter, [], async (payload, _password, { generation }) => {
    if (payload.failEncryption) throw new Error('encryption failed');
    return { id: 'current', generation, payload };
  });
  await store.loadCurrent();
  await assert.rejects(store.commit({ failEncryption: true }));
  assert.deepEqual(adapter.current, initial);
  assert.equal(store.getStatus().state, 'save-failed');
  adapter.failNext(new Error('adapter failed'));
  await assert.rejects(store.commit({ value: 2 }));
  assert.deepEqual(adapter.current, initial);
  assert.equal(store.getStatus().generation, 4);
});

test('IndexedDB adapter - reloads one current record and preserves it after abort', async () => {
  const indexedDB = fakeIndexedDB();
  const adapter = new IndexedDBVaultAdapter({ indexedDB, databaseName: 'test-vault' });
  const first = { id: 'current', generation: 1, payload: { value: 1 } };
  await adapter.putCurrent(first);
  const reloaded = new IndexedDBVaultAdapter({ indexedDB, databaseName: 'test-vault' });
  assert.deepEqual(await reloaded.getCurrent(), first);
  assert.equal(indexedDB.records.size, 1);
  indexedDB.failNext = true;
  await assert.rejects(reloaded.putCurrent({ id: 'current', generation: 2 }));
  assert.deepEqual(await reloaded.getCurrent(), first);
});
