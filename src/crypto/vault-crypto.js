const KDF_MIN_ITERATIONS = 600000;
const KDF_MAX_ITERATIONS = 2000000;
const MAX_CIPHERTEXT_BYTES = 16 * 1024 * 1024;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE32 = /^[A-Z2-7]{8,128}$/;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function fail(code, message = code) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function integer(value, min, max, code) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(code);
  return value;
}
function string(value, max, code) {
  if (typeof value !== 'string' || value.length > max) fail(code);
  return value;
}
function bytes(value, code) {
  if (!(value instanceof Uint8Array)) fail(code);
  return value;
}

export function encodeBase64(value) {
  const input = bytes(value, 'invalid_bytes');
  let binary = '';
  for (let i = 0; i < input.length; i += 0x8000) binary += String.fromCharCode(...input.subarray(i, i + 0x8000));
  if (typeof btoa === 'function') return btoa(binary);
  if (typeof Buffer !== 'undefined') return Buffer.from(binary, 'binary').toString('base64');
  fail('base64_unavailable');
}

export function decodeBase64(value) {
  if (typeof value !== 'string' || !BASE64.test(value)) fail('invalid_base64');
  let binary;
  try {
    binary = typeof atob === 'function' ? atob(value) : Buffer.from(value, 'base64').toString('binary');
  } catch {
    fail('invalid_base64');
  }
  const output = Uint8Array.from(binary, character => character.charCodeAt(0));
  if (encodeBase64(output) !== value) fail('invalid_base64');
  return output;
}

export function buildVaultAAD(generation) {
  integer(generation, 1, Number.MAX_SAFE_INTEGER, 'invalid_generation');
  return `AeroPad|vault|v2|generation=${generation}`;
}

function validateNote(note) {
  if (!object(note)) fail('invalid_note');
  string(note.id, 256, 'invalid_note'); string(note.title, 512, 'invalid_note');
  string(note.content, 1024 * 1024, 'invalid_note'); integer(note.updatedAt, 0, Number.MAX_SAFE_INTEGER, 'invalid_note');
  if (!Array.isArray(note.tags) || note.tags.length > 32) fail('invalid_note');
  note.tags.forEach(tag => string(tag, 64, 'invalid_note'));
}

function validateAccount(account) {
  if (!object(account)) fail('invalid_totp');
  string(account.id, 256, 'invalid_totp'); string(account.issuer, 256, 'invalid_totp');
  string(account.account, 256, 'invalid_totp');
  if (!BASE32.test(account.secret) || ![6, 8].includes(account.digits) || !Number.isInteger(account.period) || account.period < 1 || account.period > 3600 || !['SHA1', 'SHA256', 'SHA512'].includes(account.algo)) fail('invalid_totp');
  if (account.password !== undefined) string(account.password, 1024, 'invalid_totp');
}

export function validateVaultPayload(payload) {
  if (!object(payload) || payload.schemaVersion !== 2 || !Array.isArray(payload.notes) || payload.notes.length > 2000 || !Array.isArray(payload.totpAccounts) || payload.totpAccounts.length > 1000 || !object(payload.metadata)) fail('invalid_payload');
  payload.notes.forEach(validateNote); payload.totpAccounts.forEach(validateAccount);
  integer(payload.metadata.createdAt, 0, Number.MAX_SAFE_INTEGER, 'invalid_payload');
  integer(payload.metadata.updatedAt, 0, Number.MAX_SAFE_INTEGER, 'invalid_payload');
  return payload;
}

export function validateVaultEnvelope(envelope) {
  if (!object(envelope) || envelope.id !== 'current' || envelope.format !== 'aeropad-vault' || envelope.version !== 2 || !object(envelope.kdf) || !object(envelope.cipher)) fail('invalid_envelope');
  const generation = integer(envelope.generation, 1, Number.MAX_SAFE_INTEGER, 'invalid_generation');
  if (envelope.kdf.name !== 'PBKDF2-SHA256') fail('invalid_kdf');
  const iterations = integer(envelope.kdf.iterations, KDF_MIN_ITERATIONS, KDF_MAX_ITERATIONS, 'invalid_iterations');
  const salt = decodeBase64(envelope.kdf.salt);
  if (salt.length !== 16) fail('invalid_salt');
  if (envelope.cipher.name !== 'AES-256-GCM') fail('invalid_cipher');
  const iv = decodeBase64(envelope.cipher.iv);
  if (iv.length !== 12) fail('invalid_iv');
  if (envelope.cipher.aad !== buildVaultAAD(generation)) fail('invalid_aad');
  const ciphertext = decodeBase64(envelope.ciphertext);
  if (ciphertext.length < 16 || ciphertext.length > MAX_CIPHERTEXT_BYTES) fail('invalid_ciphertext');
  return { generation, iterations, salt, iv, ciphertext };
}

async function cryptoApi(override) {
  if (override?.subtle) return override;
  if (globalThis.crypto?.subtle) return globalThis.crypto;
  fail('crypto_unavailable', 'Web Crypto is unavailable');
}

function randomBytes(api, length, code) {
  if (typeof api.getRandomValues !== 'function') fail(code);
  return api.getRandomValues(new Uint8Array(length));
}

export async function deriveVaultKey(password, salt, iterations = KDF_MIN_ITERATIONS, options = {}) {
  if (typeof password !== 'string' || password.length === 0) fail('invalid_password');
  const validSalt = bytes(salt, 'invalid_salt'); const validIterations = integer(iterations, KDF_MIN_ITERATIONS, KDF_MAX_ITERATIONS, 'invalid_iterations'); const api = await cryptoApi(options.crypto);
  const material = await api.subtle.importKey('raw', textEncoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return api.subtle.deriveKey({ name: 'PBKDF2', salt: validSalt, iterations: validIterations, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function encryptVault(payload, password, options = {}) {
  validateVaultPayload(payload);
  const generation = integer(options.generation ?? 1, 1, Number.MAX_SAFE_INTEGER, 'invalid_generation');
  const iterations = integer(options.iterations ?? KDF_MIN_ITERATIONS, KDF_MIN_ITERATIONS, KDF_MAX_ITERATIONS, 'invalid_iterations');
  const api = await cryptoApi(options.crypto);
  const salt = options.salt ? bytes(options.salt, 'invalid_salt') : randomBytes(api, 16, 'random_unavailable');
  const iv = options.iv ? bytes(options.iv, 'invalid_iv') : randomBytes(api, 12, 'random_unavailable');
  if (salt.length !== 16) fail('invalid_salt'); if (iv.length !== 12) fail('invalid_iv');
  const aad = buildVaultAAD(generation);
  const key = await deriveVaultKey(password, salt, iterations, { crypto: api });
  const ciphertext = new Uint8Array(await api.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: textEncoder.encode(aad), tagLength: 128 }, key, textEncoder.encode(JSON.stringify(payload))));
  if (ciphertext.length > MAX_CIPHERTEXT_BYTES) fail('invalid_ciphertext');
  return { id: 'current', format: 'aeropad-vault', version: 2, generation, kdf: { name: 'PBKDF2-SHA256', iterations, salt: encodeBase64(salt) }, cipher: { name: 'AES-256-GCM', iv: encodeBase64(iv), aad }, ciphertext: encodeBase64(ciphertext) };
}

export async function decryptVault(envelope, password, options = {}) {
  const parsed = validateVaultEnvelope(envelope);
  const api = await cryptoApi(options.crypto);
  const key = await deriveVaultKey(password, parsed.salt, parsed.iterations, { crypto: api });
  let plaintext;
  try {
    plaintext = await api.subtle.decrypt({ name: 'AES-GCM', iv: parsed.iv, additionalData: textEncoder.encode(buildVaultAAD(parsed.generation)), tagLength: 128 }, key, parsed.ciphertext);
  } catch {
    fail('authentication_failed', 'Unable to decrypt vault');
  }
  let payload;
  try { payload = JSON.parse(textDecoder.decode(plaintext)); } catch { fail('invalid_payload', 'Invalid vault payload'); }
  return validateVaultPayload(payload);
}
