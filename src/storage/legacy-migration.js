import { decodeBase64, validateVaultPayload } from '../crypto/vault-crypto.js';

const KEYS = ['aeropad_notes', 'aeropad_totp'];
const BACKUPS = ['aeropad_notes_corrupt_backup', 'aeropad_totp_corrupt_backup'];
const MAX_ITERATIONS = 2000000;
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

function rawSnapshot(storage) {
  return Object.fromEntries([...KEYS, ...BACKUPS].map(key => [key, storage.getItem(key)]));
}
const recovery = (reason, raw) => ({ state: 'legacy-recovery-required', reason, raw });

function classify(raw) {
  if (raw === null) return { kind: 'missing' };
  try {
    const value = JSON.parse(raw);
    if (Array.isArray(value)) return { kind: 'plain', value };
    if (isObject(value) && value.v === 1 && value.enc === 'AES-GCM-256') return { kind: 'envelope', value };
  } catch {}
  return { kind: 'malformed' };
}

function validateEnvelope(value) {
  try {
    if (!isObject(value) || value.kdf !== 'PBKDF2-SHA256' || !Number.isSafeInteger(value.iter) || value.iter < 1 || value.iter > MAX_ITERATIONS) return null;
    const salt = decodeBase64(value.salt); const iv = decodeBase64(value.iv); const ciphertext = decodeBase64(value.ct);
    if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16 || ciphertext.length > 16 * 1024 * 1024) return null;
    return { ...value, saltBytes: salt, ivBytes: iv, ciphertextBytes: ciphertext };
  } catch { return null; }
}

function normalizePayload(notes, accounts) {
  const now = Date.now();
  const payload = {
    schemaVersion: 2,
    notes: notes.map(note => ({ ...note, tags: note.tags === undefined ? [] : note.tags, updatedAt: note.updatedAt === undefined ? now : note.updatedAt })),
    totpAccounts: accounts.map(account => ({ ...account, secret: typeof account.secret === 'string' ? account.secret.replace(/[\s-]/g, '').toUpperCase() : account.secret, password: account.password === undefined ? '' : account.password, digits: account.digits ?? 6, period: account.period ?? 30, algo: String(account.algo ?? 'SHA1').toUpperCase().replace(/-/g, '') })),
    metadata: { createdAt: now, updatedAt: now }
  };
  return validateVaultPayload(payload);
}

async function cryptoApi(override) {
  if (override?.subtle) return override;
  if (globalThis.crypto?.subtle) return globalThis.crypto;
  const error = new Error('Web Crypto is unavailable');
  error.code = 'crypto_unavailable';
  throw error;
}

export async function readLegacyVault(storage, { password, crypto } = {}) {
  const raw = rawSnapshot(storage);
  if (BACKUPS.some(key => raw[key] !== null)) return recovery('plaintext-corrupt-backup', raw);
  const notes = classify(raw.aeropad_notes); const accounts = classify(raw.aeropad_totp);
  if (notes.kind === 'missing' && accounts.kind === 'missing') return { state: 'empty', payload: null, raw };
  if (notes.kind === 'missing' || accounts.kind === 'missing') return recovery('one-sided', raw);
  if (notes.kind === 'malformed' || accounts.kind === 'malformed') return recovery('malformed', raw);
  if (notes.kind !== accounts.kind) return recovery('mixed-mode', raw);
  if (notes.kind === 'plain') {
    try { return { state: 'ready', payload: normalizePayload(notes.value, accounts.value), raw }; } catch { return recovery('malformed', raw); }
  }

  const notesEnvelope = validateEnvelope(notes.value); const accountsEnvelope = validateEnvelope(accounts.value);
  if (!notesEnvelope || !accountsEnvelope) return recovery('malformed', raw);
  if (notesEnvelope.salt !== accountsEnvelope.salt || notesEnvelope.iter !== accountsEnvelope.iter) return recovery('mixed-generation', raw);
  if (typeof password !== 'string' || password.length === 0) return recovery('password-required', raw);
  try {
    const api = await cryptoApi(crypto);
    const material = await api.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await api.subtle.deriveKey({ name: 'PBKDF2', salt: notesEnvelope.saltBytes, iterations: notesEnvelope.iter, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const decrypt = async envelope => JSON.parse(new TextDecoder().decode(await api.subtle.decrypt({ name: 'AES-GCM', iv: envelope.ivBytes }, key, envelope.ciphertextBytes)));
    const decryptedNotes = await decrypt(notesEnvelope); const decryptedAccounts = await decrypt(accountsEnvelope);
    if (!Array.isArray(decryptedNotes) || !Array.isArray(decryptedAccounts)) return recovery('malformed', raw);
    return { state: 'ready', payload: normalizePayload(decryptedNotes, decryptedAccounts), raw };
  } catch { return recovery('decrypt-failed', raw); }
}

export function completeLegacyMigration(storage) {
  const failed = [];
  for (const key of [...KEYS, ...BACKUPS]) {
    try { storage.removeItem(key); } catch { failed.push(key); }
  }
  return { failed };
}
