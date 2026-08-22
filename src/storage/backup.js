import { decryptVault, validateVaultEnvelope } from '../crypto/vault-crypto.js';

const MAX_BACKUP_BYTES = 24 * 1024 * 1024;

function fail(code, message = code) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

async function cryptoApi(override) {
  if (override?.subtle) return override;
  if (globalThis.crypto?.subtle) return globalThis.crypto;
  fail('crypto_unavailable', 'Web Crypto is unavailable');
}

async function checksumFor(envelope, crypto) {
  const api = await cryptoApi(crypto);
  const digest = new Uint8Array(await api.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(envelope))));
  return [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function validateOuterShape(backup) {
  if (!object(backup) || backup.format !== 'aeropad-backup') fail('invalid_backup');
  if (backup.version !== 1) fail('invalid_backup_version');
  if (!Number.isSafeInteger(backup.createdAt) || backup.createdAt < 0) fail('invalid_backup');
  if (!object(backup.envelope) || !object(backup.checksum)) fail('invalid_backup');
  if (backup.checksum.algorithm !== 'SHA-256' || !/^[a-f0-9]{64}$/.test(backup.checksum.value)) fail('invalid_backup_checksum');
}

function validateEnvelope(envelope) {
  try {
    validateVaultEnvelope(envelope);
  } catch {
    fail('invalid_backup_envelope');
  }
}

export async function createBackup(envelope, { createdAt = Date.now(), crypto } = {}) {
  validateEnvelope(envelope);
  const result = {
    format: 'aeropad-backup',
    version: 1,
    createdAt,
    envelope,
    checksum: { algorithm: 'SHA-256', value: await checksumFor(envelope, crypto) }
  };
  validateOuterShape(result);
  return result;
}

export function serializeBackup(backup) {
  validateOuterShape(backup);
  return JSON.stringify(backup);
}

export async function parseBackup(input, { crypto } = {}) {
  if (typeof input !== 'string' || input.length === 0 || input.length > MAX_BACKUP_BYTES) fail('invalid_backup');
  let backup;
  try { backup = JSON.parse(input); } catch { fail('invalid_backup'); }
  validateOuterShape(backup);
  const actual = await checksumFor(backup.envelope, crypto);
  if (actual !== backup.checksum.value) fail('backup_checksum_mismatch');
  validateEnvelope(backup.envelope);
  return backup;
}

export async function restoreBackup(adapter, input, password, { crypto } = {}) {
  if (!adapter || typeof adapter.putCurrent !== 'function') fail('invalid_backup_adapter');
  const backup = await parseBackup(typeof input === 'string' ? input : serializeBackup(input), { crypto });
  const payload = await decryptVault(backup.envelope, password, { crypto });
  await adapter.putCurrent(backup.envelope);
  return { ...backup, payload };
}
