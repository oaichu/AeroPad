import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { completeLegacyMigration, readLegacyVault } from '../src/storage/legacy-migration.js';

const password = 'legacy-password';
const notes = [{ id: 'n1', title: 'Old note', content: 'keep me', updatedAt: 1 }];
const accounts = [{ id: 't1', issuer: 'Example', account: 'u@example.com', secret: 'JBSWY3DPEHPK3PXP' }];

function storage(seed = {}) {
  const data = new Map(Object.entries(seed));
  return {
    getItem: key => data.has(key) ? data.get(key) : null,
    setItem: (key, value) => data.set(key, String(value)),
    removeItem: key => data.delete(key)
  };
}

async function legacyEnvelope(value, saltByte = 1) {
  const salt = new Uint8Array(16).fill(saltByte);
  const iv = new Uint8Array(12).fill(saltByte + 1);
  const material = await webcrypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await webcrypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const ciphertext = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(value)));
  const b64 = bytes => Buffer.from(bytes).toString('base64');
  return { v: 1, enc: 'AES-GCM-256', kdf: 'PBKDF2-SHA256', iter: 1000, salt: b64(salt), iv: b64(iv), ct: b64(new Uint8Array(ciphertext)) };
}

test('Legacy migration - imports two plaintext arrays without deleting raw values', async () => {
  const rawNotes = JSON.stringify(notes);
  const rawAccounts = JSON.stringify(accounts);
  const source = storage({ aeropad_notes: rawNotes, aeropad_totp: rawAccounts });
  const result = await readLegacyVault(source);
  assert.equal(result.state, 'ready');
  assert.deepEqual(result.payload.notes[0].tags, []);
  assert.equal(result.payload.totpAccounts[0].algo, 'SHA1');
  assert.equal(source.getItem('aeropad_notes'), rawNotes);
  assert.equal(source.getItem('aeropad_totp'), rawAccounts);
});

test('Legacy migration - decrypts two compatible v1 envelopes only with the password', async () => {
  const source = storage({
    aeropad_notes: JSON.stringify(await legacyEnvelope(notes)),
    aeropad_totp: JSON.stringify(await legacyEnvelope(accounts))
  });
  const result = await readLegacyVault(source, { password, crypto: webcrypto });
  assert.equal(result.state, 'ready');
  assert.equal(result.payload.notes[0].content, 'keep me');
  assert.equal(result.payload.totpAccounts[0].secret, accounts[0].secret);
  const wrong = await readLegacyVault(source, { password: 'wrong', crypto: webcrypto });
  assert.equal(wrong.state, 'legacy-recovery-required');
  assert.equal(wrong.reason, 'decrypt-failed');
});

test('Legacy migration - never treats ambiguous or corrupt input as an empty side', async () => {
  const mixed = storage({
    aeropad_notes: JSON.stringify(await legacyEnvelope(notes, 1)),
    aeropad_totp: JSON.stringify(await legacyEnvelope(accounts, 2))
  });
  for (const [source, reason] of [
    [storage({ aeropad_notes: JSON.stringify(await legacyEnvelope(notes)) }), 'one-sided'],
    [mixed, 'mixed-generation'],
    [storage({ aeropad_notes: 'not-json', aeropad_totp: JSON.stringify(accounts) }), 'malformed'],
    [storage({ aeropad_notes: JSON.stringify(notes), aeropad_totp: JSON.stringify(accounts), aeropad_notes_corrupt_backup: 'secret residue' }), 'plaintext-corrupt-backup']
  ]) {
    const result = await readLegacyVault(source, { password, crypto: webcrypto });
    assert.equal(result.reason, reason);
    assert.equal(source.getItem('aeropad_notes_corrupt_backup'), reason === 'plaintext-corrupt-backup' ? 'secret residue' : null);
  }
});

test('Legacy migration - cleanup is explicit after the v2 commit', async () => {
  const source = storage({ aeropad_notes: 'n', aeropad_totp: 't', aeropad_notes_corrupt_backup: 'backup' });
  completeLegacyMigration(source);
  assert.equal(source.getItem('aeropad_notes'), null);
  assert.equal(source.getItem('aeropad_totp'), null);
  assert.equal(source.getItem('aeropad_notes_corrupt_backup'), null);
});
