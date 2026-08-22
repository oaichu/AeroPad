import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { encryptVault, decryptVault } from '../src/crypto/vault-crypto.js';
import { createBackup, parseBackup, restoreBackup } from '../src/storage/backup.js';

const PASSWORD = 'backup password';
const SECRET = 'JBSWY3DPEHPK3PXP';
const payload = {
  schemaVersion: 2,
  notes: [{ id: 'note-1', title: 'Recovery', content: 'keep', tags: [], updatedAt: 1755800000000 }],
  totpAccounts: [{ id: 'totp-1', issuer: 'Example', account: 'user@example.io', secret: SECRET, password: 'account-pass', digits: 6, period: 30, algo: 'SHA1' }],
  metadata: { createdAt: 1755800000000, updatedAt: 1755800000000 }
};

async function envelope(generation = 7) {
  return encryptVault(payload, PASSWORD, {
    generation,
    salt: new Uint8Array(16).fill(7),
    iv: new Uint8Array(12).fill(8),
    crypto: webcrypto
  });
}

async function backup(generation = 7) {
  return createBackup(await envelope(generation), { createdAt: 1755800000000, crypto: webcrypto });
}

function memoryAdapter(current = null) {
  return {
    current,
    async getCurrent() { return this.current; },
    async putCurrent(record) { this.current = structuredClone(record); }
  };
}

test('Backup - creates a versioned checksum-verified encrypted file shape', async () => {
  const sourceEnvelope = await envelope();
  const result = await createBackup(sourceEnvelope, { createdAt: 1755800000000, crypto: webcrypto });
  const digest = await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(sourceEnvelope)));
  const expectedChecksum = Buffer.from(digest).toString('hex');

  assert.equal(result.format, 'aeropad-backup');
  assert.equal(result.version, 1);
  assert.equal(result.createdAt, 1755800000000);
  assert.equal(result.checksum.algorithm, 'SHA-256');
  assert.equal(result.checksum.value, expectedChecksum);
  assert.ok(!JSON.stringify(result).includes(SECRET));
  assert.deepEqual((await parseBackup(JSON.stringify(result), { crypto: webcrypto })).envelope, sourceEnvelope);
});

test('Backup - rejects malformed, version-tampered, and checksum-tampered files', async () => {
  const source = await backup();
  await assert.rejects(() => parseBackup('{"format":"aeropad-backup"}', { crypto: webcrypto }), /invalid_backup/);
  await assert.rejects(() => parseBackup(JSON.stringify({ ...source, version: 2 }), { crypto: webcrypto }), /invalid_backup_version/);
  const tampered = { ...source, envelope: { ...source.envelope, ciphertext: source.envelope.ciphertext.slice(0, -2) + 'AA' } };
  await assert.rejects(() => parseBackup(JSON.stringify(tampered), { crypto: webcrypto }), /backup_checksum_mismatch/);
});

test('Backup - wrong password leaves the current record untouched', async () => {
  const current = await envelope(3);
  const adapter = memoryAdapter(current);
  const imported = await backup(9);

  await assert.rejects(
    () => restoreBackup(adapter, imported, 'wrong password', { crypto: webcrypto }),
    error => error.code === 'authentication_failed'
  );
  assert.deepEqual(adapter.current, current);
});

test('Backup - verifies the password before atomically restoring into a fresh profile', async () => {
  const imported = await backup(9);
  const adapter = memoryAdapter();

  const restored = await restoreBackup(adapter, JSON.stringify(imported), PASSWORD, { crypto: webcrypto });
  assert.equal(restored.envelope.generation, 9);
  assert.equal(adapter.current.generation, 9);
  assert.deepEqual(await decryptVault(adapter.current, PASSWORD, { crypto: webcrypto }), payload);
});
