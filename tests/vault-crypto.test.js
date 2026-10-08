import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { decryptVault, encryptVault, buildVaultAAD, sanitizeVaultPayloadIds } from '../src/crypto/vault-crypto.js';
const password = 'correct horse battery staple'; const payload = {
  schemaVersion: 2,
  notes: [{ id: 'n1', title: 'Ops', content: 'rotate keys', tags: ['security'], updatedAt: 1 }],
  totpAccounts: [{ id: 't1', issuer: 'Example', account: 'user@example.com', secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30, algo: 'SHA1' }],
  metadata: { createdAt: 1, updatedAt: 1 }
};
async function fixture() {
  return encryptVault(payload, password, {
    crypto: webcrypto,
    generation: 7,
    salt: new Uint8Array(16).fill(1),
    iv: new Uint8Array(12).fill(2)
  });
}
test('Vault crypto - encrypts and decrypts a v2 payload with generation AAD', async () => {
  const envelope = await fixture();
  assert.equal(envelope.format, 'aeropad-vault');
  assert.equal(envelope.version, 2);
  assert.equal(envelope.generation, 7);
  assert.equal(envelope.cipher.aad, buildVaultAAD(7));
  assert.deepEqual(await decryptVault(envelope, password, { crypto: webcrypto }), payload);
});
test('Vault crypto - rejects a wrong password and tampered generation/AAD', async () => {
  const envelope = await fixture();
  await assert.rejects(decryptVault(envelope, 'wrong password', { crypto: webcrypto }));
  await assert.rejects(
    decryptVault({ ...envelope, generation: 8 }, password, { crypto: webcrypto }),
    error => error.code === 'invalid_aad'
  );
  await assert.rejects(
    decryptVault({ ...envelope, cipher: { ...envelope.cipher, aad: 'tampered' } }, password, { crypto: webcrypto }),
    error => error.code === 'invalid_aad'
  );
});
test('Vault crypto - rejects malformed Base64 and invalid salt/IV lengths', async () => {
  const envelope = await fixture();
  await assert.rejects(decryptVault({ ...envelope, ciphertext: '%%%%' }, password), error => error.code === 'invalid_base64');
  await assert.rejects(decryptVault({ ...envelope, kdf: { ...envelope.kdf, salt: Buffer.alloc(15).toString('base64') } }, password), error => error.code === 'invalid_salt');
  await assert.rejects(decryptVault({ ...envelope, cipher: { ...envelope.cipher, iv: Buffer.alloc(13).toString('base64') } }, password), error => error.code === 'invalid_iv');
});
test('Vault crypto - rejects bounded-envelope violations before deriveKey', async () => {
  const envelope = await fixture();
  let deriveCalls = 0;
  const deriveSpy = { subtle: { deriveKey() { deriveCalls += 1; throw new Error('deriveKey must not run'); } } };
  const cases = [
    { ...envelope, kdf: { ...envelope.kdf, iterations: 599999 } },
    { ...envelope, kdf: { ...envelope.kdf, iterations: 2000001 } },
    { ...envelope, ciphertext: Buffer.alloc(16 * 1024 * 1024 + 2).toString('base64') }
  ];
  for (const candidate of cases) {
    await assert.rejects(decryptVault(candidate, password, { crypto: deriveSpy }));
  }
  assert.equal(deriveCalls, 0);
});

test('Vault payload - re-keys hostile and duplicate record ids before the DOM sees them', () => {
  let counter = 0;
  const makeId = prefix => `${prefix}-new-${counter++}`;
  const hostileId = 'x"><img src=x onerror=alert(1)>';
  const dirty = {
    ...payload,
    notes: [
      { id: 'ok-note', title: 'a', content: '', tags: [], updatedAt: 1 },
      { id: hostileId, title: 'b', content: '', tags: [], updatedAt: 2 }
    ],
    totpAccounts: [
      { id: 'totp-same', issuer: 'A', account: 'a@x.io', secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30, algo: 'SHA1' },
      { id: 'totp-same', issuer: 'B', account: 'b@x.io', secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30, algo: 'SHA1' },
      { id: hostileId, issuer: 'C', account: 'c@x.io', secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30, algo: 'SHA1' }
    ]
  };
  const clean = sanitizeVaultPayloadIds(dirty, makeId);
  assert.equal(clean.notes[0].id, 'ok-note');
  assert.match(clean.notes[1].id, /^note-new-/);
  const accountIds = clean.totpAccounts.map(account => account.id);
  assert.deepEqual([...new Set(accountIds)].length, 3);
  assert.ok(accountIds.every(id => /^[A-Za-z0-9_-]{1,64}$/.test(id)));
  assert.equal(clean.totpAccounts[0].id, 'totp-same');
  assert.equal(clean.totpAccounts[2].issuer, 'C');
});
