var __typeError = (msg) => {
  throw TypeError(msg);
};
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateMethod = (obj, member, method) => (__accessCheck(obj, member, "access private method"), method);

// src/crypto/base32.js
var Base32 = {
  alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
  decode(input) {
    if (!input || typeof input !== "string") {
      return new Uint8Array(0).buffer;
    }
    const cleanInput = input.toUpperCase().replace(/[\s=-]/g, "");
    const length = cleanInput.length;
    let bits = 0;
    let value = 0;
    let index = 0;
    const output = new Uint8Array(Math.floor(length * 5 / 8));
    for (let i = 0; i < length; i++) {
      const char = cleanInput[i];
      const val = this.alphabet.indexOf(char);
      if (val === -1) {
        return new Uint8Array(0).buffer;
      }
      value = value << 5 | val;
      bits += 5;
      if (bits >= 8) {
        output[index++] = value >>> bits - 8 & 255;
        bits -= 8;
      }
    }
    return output.buffer;
  },
  encode(buffer) {
    if (!buffer) return "";
    const bytes2 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let bits = 0;
    let value = 0;
    let output = "";
    for (let i = 0; i < bytes2.length; i++) {
      value = value << 8 | bytes2[i];
      bits += 8;
      while (bits >= 5) {
        output += this.alphabet[value >>> bits - 5 & 31];
        bits -= 5;
      }
    }
    if (bits > 0) {
      output += this.alphabet[value << 5 - bits & 31];
    }
    return output;
  },
  randomSecret(length = 32) {
    let result = "";
    const bytes2 = new Uint8Array(length);
    if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
      globalThis.crypto.getRandomValues(bytes2);
    } else {
      throw new Error("No cryptographically secure RNG available in this environment");
    }
    for (let i = 0; i < length; i++) {
      result += this.alphabet[bytes2[i] % this.alphabet.length];
    }
    return result;
  }
};

// src/crypto/otpauth.js
function buildOTPAuthURI(options = {}) {
  const {
    issuer = "AetherPad",
    account = "user",
    secret = "",
    digits = 6,
    period = 30,
    algo = "SHA1"
  } = options;
  const encIssuer = encodeURIComponent(issuer.trim());
  const encAccount = encodeURIComponent(account.trim());
  const cleanSecret = secret.replace(/[\s-]/g, "").toUpperCase();
  return `otpauth://totp/${encIssuer}:${encAccount}?secret=${cleanSecret}&issuer=${encIssuer}&algorithm=${algo}&digits=${digits}&period=${period}`;
}
var MIN_PERIOD = 1;
var MAX_PERIOD = 3600;
function invalid(errorCode, error) {
  return { isValid: false, errorCode, error };
}
function normalizeSecret(value) {
  const cleaned = String(value).replace(/[\s-]/g, "").toUpperCase();
  if (!/^[A-Z2-7]+={0,6}$/.test(cleaned)) {
    return null;
  }
  const unpadded = cleaned.replace(/=+$/, "");
  return /^[A-Z2-7]{8,128}$/.test(unpadded) ? unpadded : null;
}
function normalizeAlgorithm(value) {
  const normalized = String(value).toUpperCase().replace(/-/g, "");
  if (normalized === "SHA1" || normalized === "SHA256" || normalized === "SHA512") {
    return normalized;
  }
  return null;
}
function parseIntegerParam(url, name, defaultValue, min, max, errorCode) {
  const raw = url.searchParams.get(name);
  if (raw === null) {
    return { value: defaultValue };
  }
  if (!/^\d+$/.test(raw)) {
    return { error: invalid(errorCode, `Invalid ${name} parameter`) };
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    return { error: invalid(errorCode, `Invalid ${name} parameter`) };
  }
  return { value };
}
function parseOTPAuthURI(input) {
  if (!input || typeof input !== "string") {
    return invalid("empty_input", "Empty input");
  }
  const trimmed = input.trim();
  if (trimmed.toLowerCase().startsWith("otpauth://")) {
    try {
      const url = new URL(trimmed);
      if (url.protocol.toLowerCase() !== "otpauth:") {
        return invalid("invalid_protocol", "Invalid protocol");
      }
      if (url.hostname.toLowerCase() !== "totp" || url.port) {
        return invalid("unsupported_type", "Only otpauth://totp/... URIs are supported");
      }
      const label = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
      const separator = label.indexOf(":");
      const labelIssuer = separator === -1 ? "" : label.slice(0, separator);
      const labelAccount = separator === -1 ? label : label.slice(separator + 1);
      const issuer = url.searchParams.get("issuer")?.trim() || labelIssuer || "Custom 2FA";
      const account = labelAccount || "User";
      const secretParam = url.searchParams.get("secret");
      if (secretParam === null || secretParam.trim() === "") {
        return invalid("missing_secret", "Missing secret parameter");
      }
      const secret = normalizeSecret(secretParam);
      if (!secret) {
        return invalid("invalid_secret", "Invalid Base32 secret");
      }
      const algorithmParam = url.searchParams.get("algorithm");
      const algo = normalizeAlgorithm(algorithmParam === null ? "SHA1" : algorithmParam);
      if (!algo) {
        return invalid("unsupported_algorithm", "Unsupported algorithm");
      }
      const digitsResult = parseIntegerParam(url, "digits", 6, 6, 8, "invalid_digits");
      if (digitsResult.error) {
        return digitsResult.error;
      }
      if (digitsResult.value !== 6 && digitsResult.value !== 8) {
        return invalid("invalid_digits", "Digits must be 6 or 8");
      }
      const periodResult = parseIntegerParam(url, "period", 30, MIN_PERIOD, MAX_PERIOD, "invalid_period");
      if (periodResult.error) {
        return periodResult.error;
      }
      return {
        isValid: true,
        type: "totp",
        issuer,
        account,
        secret,
        digits: digitsResult.value,
        period: periodResult.value,
        algo
      };
    } catch {
      return invalid("invalid_uri", "Invalid URI");
    }
  }
  const cleanBase32 = normalizeSecret(trimmed);
  if (cleanBase32) {
    return {
      isValid: true,
      type: "totp",
      issuer: "Direct Key",
      account: "Account",
      secret: cleanBase32,
      digits: 6,
      period: 30,
      algo: "SHA1"
    };
  }
  return invalid("unrecognized_format", "Unrecognized format");
}

// src/crypto/totp.js
var MIN_PERIOD2 = 1;
var MAX_PERIOD2 = 3600;
var SUPPORTED_DIGITS = /* @__PURE__ */ new Set([6, 8]);
function normalizeAlgorithm2(algo = "SHA-1") {
  const clean = String(algo).toUpperCase().replace(/-/g, "");
  if (clean === "SHA1") return "SHA-1";
  if (clean === "SHA256") return "SHA-256";
  if (clean === "SHA512") return "SHA-512";
  return null;
}
function isValidPeriod(period) {
  return Number.isInteger(period) && period >= MIN_PERIOD2 && period <= MAX_PERIOD2;
}
function isValidTimestamp(timestamp) {
  return Number.isInteger(timestamp) && timestamp >= 0;
}
async function generateTOTP(secretBase32, options = {}) {
  const {
    period = 30,
    digits = 6,
    algo = "SHA-1",
    timestamp = Math.floor(Date.now() / 1e3)
  } = options;
  try {
    const normalizedAlgo = normalizeAlgorithm2(algo);
    if (!secretBase32 || typeof secretBase32 !== "string" || !isValidPeriod(period) || !SUPPORTED_DIGITS.has(digits) || !normalizedAlgo || !isValidTimestamp(timestamp)) {
      return null;
    }
    const keyBytes = Base32.decode(secretBase32);
    if (keyBytes.byteLength === 0) {
      return null;
    }
    const counter = Math.floor(timestamp / period);
    const counterBuffer = new ArrayBuffer(8);
    const counterView = new DataView(counterBuffer);
    counterView.setBigUint64(0, BigInt(counter), false);
    let subtleCrypto = globalThis.crypto?.subtle;
    if (!subtleCrypto) {
      const nodeCrypto = await import("node:crypto");
      subtleCrypto = nodeCrypto.webcrypto.subtle;
    }
    const cryptoKey = await subtleCrypto.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: { name: normalizedAlgo } },
      false,
      ["sign"]
    );
    const signature = await subtleCrypto.sign("HMAC", cryptoKey, counterBuffer);
    const hmacBytes = new Uint8Array(signature);
    const offset = hmacBytes[hmacBytes.length - 1] & 15;
    const binary = (hmacBytes[offset] & 127) << 24 | (hmacBytes[offset + 1] & 255) << 16 | (hmacBytes[offset + 2] & 255) << 8 | hmacBytes[offset + 3] & 255;
    const otp = binary % Math.pow(10, digits);
    return otp.toString().padStart(digits, "0");
  } catch (err) {
    console.error("TOTP Generation Error:", err);
    return null;
  }
}

// src/crypto/vault-crypto.js
var KDF_MIN_ITERATIONS = 6e5;
var KDF_MAX_ITERATIONS = 2e6;
var MAX_CIPHERTEXT_BYTES = 16 * 1024 * 1024;
var BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
var BASE32 = /^[A-Z2-7]{8,128}$/;
var textEncoder = new TextEncoder();
var textDecoder = new TextDecoder();
function fail(code, message = code) {
  const error = new Error(message);
  error.code = code;
  throw error;
}
var object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
function integer(value, min, max, code) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(code);
  return value;
}
function string(value, max, code) {
  if (typeof value !== "string" || value.length > max) fail(code);
  return value;
}
function bytes(value, code) {
  if (!(value instanceof Uint8Array)) fail(code);
  return value;
}
function encodeBase64(value) {
  const input = bytes(value, "invalid_bytes");
  let binary = "";
  for (let i = 0; i < input.length; i += 32768) binary += String.fromCharCode(...input.subarray(i, i + 32768));
  if (typeof btoa === "function") return btoa(binary);
  if (typeof Buffer !== "undefined") return Buffer.from(binary, "binary").toString("base64");
  fail("base64_unavailable");
}
function decodeBase64(value) {
  if (typeof value !== "string" || !BASE64.test(value)) fail("invalid_base64");
  let binary;
  try {
    binary = typeof atob === "function" ? atob(value) : Buffer.from(value, "base64").toString("binary");
  } catch {
    fail("invalid_base64");
  }
  const output = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64(output) !== value) fail("invalid_base64");
  return output;
}
function buildVaultAAD(generation) {
  integer(generation, 1, Number.MAX_SAFE_INTEGER, "invalid_generation");
  return `AeroPad|vault|v2|generation=${generation}`;
}
function validateNote(note) {
  if (!object(note)) fail("invalid_note");
  string(note.id, 256, "invalid_note");
  string(note.title, 512, "invalid_note");
  string(note.content, 1024 * 1024, "invalid_note");
  integer(note.updatedAt, 0, Number.MAX_SAFE_INTEGER, "invalid_note");
  if (!Array.isArray(note.tags) || note.tags.length > 32) fail("invalid_note");
  note.tags.forEach((tag) => string(tag, 64, "invalid_note"));
}
function validateAccount(account) {
  if (!object(account)) fail("invalid_totp");
  string(account.id, 256, "invalid_totp");
  string(account.issuer, 256, "invalid_totp");
  string(account.account, 256, "invalid_totp");
  if (!BASE32.test(account.secret) || ![6, 8].includes(account.digits) || !Number.isInteger(account.period) || account.period < 1 || account.period > 3600 || !["SHA1", "SHA256", "SHA512"].includes(account.algo)) fail("invalid_totp");
  if (account.password !== void 0) string(account.password, 1024, "invalid_totp");
}
function validateVaultPayload(payload) {
  if (!object(payload) || payload.schemaVersion !== 2 || !Array.isArray(payload.notes) || payload.notes.length > 2e3 || !Array.isArray(payload.totpAccounts) || payload.totpAccounts.length > 1e3 || !object(payload.metadata)) fail("invalid_payload");
  payload.notes.forEach(validateNote);
  payload.totpAccounts.forEach(validateAccount);
  integer(payload.metadata.createdAt, 0, Number.MAX_SAFE_INTEGER, "invalid_payload");
  integer(payload.metadata.updatedAt, 0, Number.MAX_SAFE_INTEGER, "invalid_payload");
  return payload;
}
function validateVaultEnvelope(envelope) {
  if (!object(envelope) || envelope.id !== "current" || envelope.format !== "aeropad-vault" || envelope.version !== 2 || !object(envelope.kdf) || !object(envelope.cipher)) fail("invalid_envelope");
  const generation = integer(envelope.generation, 1, Number.MAX_SAFE_INTEGER, "invalid_generation");
  if (envelope.kdf.name !== "PBKDF2-SHA256") fail("invalid_kdf");
  const iterations = integer(envelope.kdf.iterations, KDF_MIN_ITERATIONS, KDF_MAX_ITERATIONS, "invalid_iterations");
  const salt = decodeBase64(envelope.kdf.salt);
  if (salt.length !== 16) fail("invalid_salt");
  if (envelope.cipher.name !== "AES-256-GCM") fail("invalid_cipher");
  const iv = decodeBase64(envelope.cipher.iv);
  if (iv.length !== 12) fail("invalid_iv");
  if (envelope.cipher.aad !== buildVaultAAD(generation)) fail("invalid_aad");
  const ciphertext = decodeBase64(envelope.ciphertext);
  if (ciphertext.length < 16 || ciphertext.length > MAX_CIPHERTEXT_BYTES) fail("invalid_ciphertext");
  return { generation, iterations, salt, iv, ciphertext };
}
async function cryptoApi(override) {
  if (override?.subtle) return override;
  if (globalThis.crypto?.subtle) return globalThis.crypto;
  fail("crypto_unavailable", "Web Crypto is unavailable");
}
function randomBytes(api, length, code) {
  if (typeof api.getRandomValues !== "function") fail(code);
  return api.getRandomValues(new Uint8Array(length));
}
async function deriveVaultKey(password, salt, iterations = KDF_MIN_ITERATIONS, options = {}) {
  if (typeof password !== "string" || password.length === 0) fail("invalid_password");
  const validSalt = bytes(salt, "invalid_salt");
  const validIterations = integer(iterations, KDF_MIN_ITERATIONS, KDF_MAX_ITERATIONS, "invalid_iterations");
  const api = await cryptoApi(options.crypto);
  const material = await api.subtle.importKey("raw", textEncoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return api.subtle.deriveKey({ name: "PBKDF2", salt: validSalt, iterations: validIterations, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function encryptVault(payload, password, options = {}) {
  validateVaultPayload(payload);
  const generation = integer(options.generation ?? 1, 1, Number.MAX_SAFE_INTEGER, "invalid_generation");
  const iterations = integer(options.iterations ?? KDF_MIN_ITERATIONS, KDF_MIN_ITERATIONS, KDF_MAX_ITERATIONS, "invalid_iterations");
  const api = await cryptoApi(options.crypto);
  const salt = options.salt ? bytes(options.salt, "invalid_salt") : randomBytes(api, 16, "random_unavailable");
  const iv = options.iv ? bytes(options.iv, "invalid_iv") : randomBytes(api, 12, "random_unavailable");
  if (salt.length !== 16) fail("invalid_salt");
  if (iv.length !== 12) fail("invalid_iv");
  const aad = buildVaultAAD(generation);
  const key = await deriveVaultKey(password, salt, iterations, { crypto: api });
  const ciphertext = new Uint8Array(await api.subtle.encrypt({ name: "AES-GCM", iv, additionalData: textEncoder.encode(aad), tagLength: 128 }, key, textEncoder.encode(JSON.stringify(payload))));
  if (ciphertext.length > MAX_CIPHERTEXT_BYTES) fail("invalid_ciphertext");
  return { id: "current", format: "aeropad-vault", version: 2, generation, kdf: { name: "PBKDF2-SHA256", iterations, salt: encodeBase64(salt) }, cipher: { name: "AES-256-GCM", iv: encodeBase64(iv), aad }, ciphertext: encodeBase64(ciphertext) };
}
async function decryptVault(envelope, password, options = {}) {
  const parsed = validateVaultEnvelope(envelope);
  const api = await cryptoApi(options.crypto);
  const key = await deriveVaultKey(password, parsed.salt, parsed.iterations, { crypto: api });
  let plaintext;
  try {
    plaintext = await api.subtle.decrypt({ name: "AES-GCM", iv: parsed.iv, additionalData: textEncoder.encode(buildVaultAAD(parsed.generation)), tagLength: 128 }, key, parsed.ciphertext);
  } catch {
    fail("authentication_failed", "Unable to decrypt vault");
  }
  let payload;
  try {
    payload = JSON.parse(textDecoder.decode(plaintext));
  } catch {
    fail("invalid_payload", "Invalid vault payload");
  }
  return validateVaultPayload(payload);
}

// src/storage/indexeddb-adapter.js
var VAULT_DB_NAME = "aeropad-vault";
var VAULT_DB_VERSION = 1;
var VAULT_STORE_NAME = "vault";
var CURRENT_KEY = "current";
function asError(value, fallback) {
  if (value instanceof Error) return value;
  const error = new Error(value?.message || fallback);
  error.code = "indexeddb_error";
  return error;
}
var IndexedDBVaultAdapter = class {
  constructor({ indexedDB = globalThis.indexedDB, databaseName = VAULT_DB_NAME, version = VAULT_DB_VERSION } = {}) {
    if (!indexedDB || typeof indexedDB.open !== "function") throw new TypeError("IndexedDB is unavailable");
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
        request.onupgradeneeded = (event) => {
          const db = event.target.result;
          if (!db.objectStoreNames.contains(VAULT_STORE_NAME)) db.createObjectStore(VAULT_STORE_NAME, { keyPath: "id" });
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(asError(request.error, "Unable to open vault database"));
        request.onblocked = () => reject(asError(null, "Vault database upgrade is blocked"));
      } catch (error) {
        reject(asError(error, "Unable to open vault database"));
      }
    });
    this.dbPromise.catch(() => {
      this.dbPromise = null;
    });
    return this.dbPromise;
  }
  async getCurrent() {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let value = null;
      let settled = false;
      const fail3 = (error) => {
        if (!settled) {
          settled = true;
          reject(asError(error, "Unable to read vault"));
        }
      };
      try {
        const tx = db.transaction(VAULT_STORE_NAME, "readonly");
        tx.onerror = () => fail3(tx.error);
        tx.onabort = () => fail3(tx.error);
        tx.oncomplete = () => {
          if (!settled) {
            settled = true;
            resolve(value);
          }
        };
        const request = tx.objectStore(VAULT_STORE_NAME).get(CURRENT_KEY);
        request.onsuccess = () => {
          value = request.result ?? null;
        };
        request.onerror = () => fail3(request.error);
      } catch (error) {
        fail3(error);
      }
    });
  }
  async putCurrent(record) {
    if (!record || record.id !== CURRENT_KEY) throw asError(null, "Only the current vault record may be written");
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail3 = (error) => {
        if (!settled) {
          settled = true;
          reject(asError(error, "Unable to commit vault"));
        }
      };
      try {
        const tx = db.transaction(VAULT_STORE_NAME, "readwrite");
        tx.onerror = () => fail3(tx.error);
        tx.onabort = () => fail3(tx.error);
        tx.oncomplete = () => {
          if (!settled) {
            settled = true;
            resolve();
          }
        };
        const request = tx.objectStore(VAULT_STORE_NAME).put(record);
        request.onerror = () => fail3(request.error);
      } catch (error) {
        fail3(error);
      }
    });
  }
};

// src/storage/backup.js
var MAX_BACKUP_BYTES = 24 * 1024 * 1024;
function fail2(code, message = code) {
  const error = new Error(message);
  error.code = code;
  throw error;
}
var object2 = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
async function cryptoApi2(override) {
  if (override?.subtle) return override;
  if (globalThis.crypto?.subtle) return globalThis.crypto;
  fail2("crypto_unavailable", "Web Crypto is unavailable");
}
async function checksumFor(envelope, crypto) {
  const api = await cryptoApi2(crypto);
  const digest = new Uint8Array(await api.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(envelope))));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
function validateOuterShape(backup) {
  if (!object2(backup) || backup.format !== "aeropad-backup") fail2("invalid_backup");
  if (backup.version !== 1) fail2("invalid_backup_version");
  if (!Number.isSafeInteger(backup.createdAt) || backup.createdAt < 0) fail2("invalid_backup");
  if (!object2(backup.envelope) || !object2(backup.checksum)) fail2("invalid_backup");
  if (backup.checksum.algorithm !== "SHA-256" || !/^[a-f0-9]{64}$/.test(backup.checksum.value)) fail2("invalid_backup_checksum");
}
function validateEnvelope(envelope) {
  try {
    validateVaultEnvelope(envelope);
  } catch {
    fail2("invalid_backup_envelope");
  }
}
async function createBackup(envelope, { createdAt = Date.now(), crypto } = {}) {
  validateEnvelope(envelope);
  const result = {
    format: "aeropad-backup",
    version: 1,
    createdAt,
    envelope,
    checksum: { algorithm: "SHA-256", value: await checksumFor(envelope, crypto) }
  };
  validateOuterShape(result);
  return result;
}
function serializeBackup(backup) {
  validateOuterShape(backup);
  return JSON.stringify(backup);
}
async function parseBackup(input, { crypto } = {}) {
  if (typeof input !== "string" || input.length === 0 || input.length > MAX_BACKUP_BYTES) fail2("invalid_backup");
  let backup;
  try {
    backup = JSON.parse(input);
  } catch {
    fail2("invalid_backup");
  }
  validateOuterShape(backup);
  const actual = await checksumFor(backup.envelope, crypto);
  if (actual !== backup.checksum.value) fail2("backup_checksum_mismatch");
  validateEnvelope(backup.envelope);
  return backup;
}
async function restoreBackup(adapter, input, password, { crypto } = {}) {
  if (!adapter || typeof adapter.putCurrent !== "function") fail2("invalid_backup_adapter");
  const backup = await parseBackup(typeof input === "string" ? input : serializeBackup(input), { crypto });
  const payload = await decryptVault(backup.envelope, password, { crypto });
  await adapter.putCurrent(backup.envelope);
  return { ...backup, payload };
}

// src/storage/legacy-migration.js
var KEYS = ["aeropad_notes", "aeropad_totp"];
var BACKUPS = ["aeropad_notes_corrupt_backup", "aeropad_totp_corrupt_backup"];
var MAX_ITERATIONS = 2e6;
var isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
function rawSnapshot(storage) {
  return Object.fromEntries([...KEYS, ...BACKUPS].map((key) => [key, storage.getItem(key)]));
}
var recovery = (reason, raw) => ({ state: "legacy-recovery-required", reason, raw });
function classify(raw) {
  if (raw === null) return { kind: "missing" };
  try {
    const value = JSON.parse(raw);
    if (Array.isArray(value)) return { kind: "plain", value };
    if (isObject(value) && value.v === 1 && value.enc === "AES-GCM-256") return { kind: "envelope", value };
  } catch {
  }
  return { kind: "malformed" };
}
function validateEnvelope2(value) {
  try {
    if (!isObject(value) || value.kdf !== "PBKDF2-SHA256" || !Number.isSafeInteger(value.iter) || value.iter < 1 || value.iter > MAX_ITERATIONS) return null;
    const salt = decodeBase64(value.salt);
    const iv = decodeBase64(value.iv);
    const ciphertext = decodeBase64(value.ct);
    if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16 || ciphertext.length > 16 * 1024 * 1024) return null;
    return { ...value, saltBytes: salt, ivBytes: iv, ciphertextBytes: ciphertext };
  } catch {
    return null;
  }
}
function normalizePayload(notes, accounts) {
  const now = Date.now();
  const payload = {
    schemaVersion: 2,
    notes: notes.map((note) => ({ ...note, tags: note.tags === void 0 ? [] : note.tags, updatedAt: note.updatedAt === void 0 ? now : note.updatedAt })),
    totpAccounts: accounts.map((account) => ({ ...account, secret: typeof account.secret === "string" ? account.secret.replace(/[\s-]/g, "").toUpperCase() : account.secret, password: account.password === void 0 ? "" : account.password, digits: account.digits ?? 6, period: account.period ?? 30, algo: String(account.algo ?? "SHA1").toUpperCase().replace(/-/g, "") })),
    metadata: { createdAt: now, updatedAt: now }
  };
  return validateVaultPayload(payload);
}
async function cryptoApi3(override) {
  if (override?.subtle) return override;
  if (globalThis.crypto?.subtle) return globalThis.crypto;
  const error = new Error("Web Crypto is unavailable");
  error.code = "crypto_unavailable";
  throw error;
}
async function readLegacyVault(storage, { password, crypto } = {}) {
  const raw = rawSnapshot(storage);
  if (BACKUPS.some((key) => raw[key] !== null)) return recovery("plaintext-corrupt-backup", raw);
  const notes = classify(raw.aeropad_notes);
  const accounts = classify(raw.aeropad_totp);
  if (notes.kind === "missing" && accounts.kind === "missing") return { state: "empty", payload: null, raw };
  if (notes.kind === "missing" || accounts.kind === "missing") return recovery("one-sided", raw);
  if (notes.kind === "malformed" || accounts.kind === "malformed") return recovery("malformed", raw);
  if (notes.kind !== accounts.kind) return recovery("mixed-mode", raw);
  if (notes.kind === "plain") {
    try {
      return { state: "ready", payload: normalizePayload(notes.value, accounts.value), raw };
    } catch {
      return recovery("malformed", raw);
    }
  }
  const notesEnvelope = validateEnvelope2(notes.value);
  const accountsEnvelope = validateEnvelope2(accounts.value);
  if (!notesEnvelope || !accountsEnvelope) return recovery("malformed", raw);
  if (notesEnvelope.salt !== accountsEnvelope.salt || notesEnvelope.iter !== accountsEnvelope.iter) return recovery("mixed-generation", raw);
  if (typeof password !== "string" || password.length === 0) return recovery("password-required", raw);
  try {
    const api = await cryptoApi3(crypto);
    const material = await api.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    const key = await api.subtle.deriveKey({ name: "PBKDF2", salt: notesEnvelope.saltBytes, iterations: notesEnvelope.iter, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const decrypt = async (envelope) => JSON.parse(new TextDecoder().decode(await api.subtle.decrypt({ name: "AES-GCM", iv: envelope.ivBytes }, key, envelope.ciphertextBytes)));
    const decryptedNotes = await decrypt(notesEnvelope);
    const decryptedAccounts = await decrypt(accountsEnvelope);
    if (!Array.isArray(decryptedNotes) || !Array.isArray(decryptedAccounts)) return recovery("malformed", raw);
    return { state: "ready", payload: normalizePayload(decryptedNotes, decryptedAccounts), raw };
  } catch {
    return recovery("decrypt-failed", raw);
  }
}
function completeLegacyMigration(storage) {
  const failed = [];
  for (const key of [...KEYS, ...BACKUPS]) {
    try {
      storage.removeItem(key);
    } catch {
      failed.push(key);
    }
  }
  return { failed };
}

// src/storage/vault-store.js
function failure(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}
var _VaultStore_instances, drain_fn;
var VaultStore = class {
  constructor({ adapter, password, encrypt = encryptVault } = {}) {
    __privateAdd(this, _VaultStore_instances);
    if (!adapter || typeof adapter.getCurrent !== "function" || typeof adapter.putCurrent !== "function") throw new TypeError("Vault adapter is required");
    this.adapter = adapter;
    this.password = password;
    this.encrypt = encrypt;
    this.currentRecord = null;
    this.lastCommittedGeneration = 0;
    this.pendingPayload = void 0;
    this.hasPending = false;
    this.worker = null;
    this.status = { state: "idle", generation: 0, error: null };
  }
  async loadCurrent() {
    const record = await this.adapter.getCurrent();
    if (record && (!Number.isSafeInteger(record.generation) || record.generation < 1)) throw failure("invalid_current", "Invalid current vault record");
    this.currentRecord = record || null;
    this.lastCommittedGeneration = record?.generation ?? 0;
    this.status = { state: record ? "committed" : "idle", generation: this.lastCommittedGeneration, error: null };
    return this.currentRecord;
  }
  commit(payload) {
    this.pendingPayload = payload;
    this.hasPending = true;
    this.status = { state: "pending", generation: this.lastCommittedGeneration + 1, error: null };
    if (!this.worker) this.worker = Promise.resolve().then(() => __privateMethod(this, _VaultStore_instances, drain_fn).call(this));
    return this.worker;
  }
  async flush() {
    if (this.worker) await this.worker;
    return this.currentRecord;
  }
  getStatus() {
    return { ...this.status };
  }
};
_VaultStore_instances = new WeakSet();
drain_fn = async function() {
  try {
    while (this.hasPending) {
      const payload = this.pendingPayload;
      this.hasPending = false;
      const generation = this.lastCommittedGeneration + 1;
      this.status = { state: "pending", generation, error: null };
      const record = await this.encrypt(payload, this.password, { generation });
      if (!record || record.id !== "current" || record.generation !== generation) throw failure("invalid_envelope", "Encryption returned an invalid record");
      await this.adapter.putCurrent(record);
      this.currentRecord = record;
      this.lastCommittedGeneration = generation;
      this.status = { state: "committed", generation, error: null };
    }
    return this.currentRecord;
  } catch (error) {
    this.hasPending = false;
    this.pendingPayload = void 0;
    this.status = { state: "save-failed", generation: this.lastCommittedGeneration, error };
    throw error;
  } finally {
    this.worker = null;
  }
};

// src/notes/notes-manager.js
var NOTE_SEARCH_DEBOUNCE_MS = 125;
function normalizeSearchText(value = "") {
  return String(value ?? "").normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase().replace(/\s+/g, " ").trim();
}
var normalizedNoteCache = /* @__PURE__ */ new WeakMap();
function getNormalizedNote(note) {
  if (!note || typeof note !== "object") return { title: "", content: "" };
  const rawTitle = String(note.title ?? "");
  const rawContent = String(note.content ?? "");
  const cached = normalizedNoteCache.get(note);
  if (cached?.rawTitle === rawTitle && cached.rawContent === rawContent) return cached;
  const normalized = {
    rawTitle,
    rawContent,
    title: normalizeSearchText(rawTitle),
    content: normalizeSearchText(rawContent)
  };
  normalizedNoteCache.set(note, normalized);
  return normalized;
}
function searchNotes(notes = [], query = "") {
  const source = Array.isArray(notes) ? notes : [];
  const normalizedQuery = normalizeSearchText(query);
  if (!normalizedQuery) return [...source];
  return source.map((note, index) => {
    const normalized = getNormalizedNote(note);
    const titleIndex = normalized.title.indexOf(normalizedQuery);
    const contentIndex = normalized.content.indexOf(normalizedQuery);
    if (titleIndex < 0 && contentIndex < 0) return null;
    const titleScore = titleIndex >= 0 ? 1e3 + (titleIndex === 0 ? 100 : 0) - titleIndex : 0;
    const contentScore = contentIndex >= 0 ? 100 - contentIndex : 0;
    return { note, index, score: titleScore + contentScore };
  }).filter(Boolean).sort((a, b) => b.score - a.score || a.index - b.index).map((result) => result.note);
}

// src/app.js
var isValidBase32Secret = (secret) => parseOTPAuthURI(secret).isValid;
function formatOTPCode(code) {
  if (!code) return "------";
  const split = Math.ceil(code.length / 2);
  return code.slice(0, split) + " " + code.slice(split);
}
async function copyTextToClipboard(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (err) {
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  } catch (err) {
    return false;
  }
}
function getCurrentCardCode(accId) {
  const el = document.getElementById("code-" + accId);
  if (!el) return null;
  const code = (el.textContent || "").replace(/\s+/g, "");
  return /^\d+$/.test(code) ? code : null;
}
async function copyVaultCode(acc) {
  const code = getCurrentCardCode(acc.id);
  if (!code) {
    showToast(t("toast_invalid_code"), "error");
    return;
  }
  const ok = await copyTextToClipboard(code);
  if (ok) showToast(`${t("toast_code_copied")} ${code}`);
  else showToast(t("toast_copy_failed"), "error");
}
function generateId(prefix) {
  return prefix + "-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8);
}
function readEnvelope(key) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const obj = JSON.parse(raw);
    if (obj && obj.v === 1 && obj.enc === "AES-GCM-256" && typeof obj.ct === "string") return obj;
  } catch (err) {
  }
  return null;
}
function vaultIsEncrypted() {
  return vaultStorageMode === "v2" || !!(readEnvelope("aeropad_notes") || readEnvelope("aeropad_totp"));
}
function setVaultSaveStatus(state) {
  if (typeof document === "undefined") return;
  const indicator = document.getElementById("saveIndicator");
  if (!indicator) return;
  const labels = { pending: t("save_pending"), committed: t("save_saved"), "save-failed": t("save_failed") };
  indicator.dataset.state = state;
  const text = document.getElementById("saveIndicatorText") || indicator.querySelector("[data-i18n]");
  if (text) text.textContent = labels[state] || labels.committed;
  indicator.setAttribute("aria-label", labels[state] || labels.committed);
}
function setBackupStatus(state, message = "") {
  const status = document.getElementById("backupStatus");
  if (!status) return;
  status.dataset.state = state;
  status.textContent = message || t("backup_status_default");
}
function updateBackupStatus() {
  const raw = localStorage.getItem("aeropad_last_backup_at");
  const timestamp = Number(raw);
  if (Number.isSafeInteger(timestamp) && timestamp > 0) {
    setBackupStatus("backup-ready", `${t("backup_last_export")} ${new Date(timestamp).toLocaleString()}`);
  } else {
    setBackupStatus("backup-reminder", t("backup_status_default"));
  }
}
function readBackupFile(file) {
  if (!file || file.size > 24 * 1024 * 1024) throw new Error("backup_too_large");
  if (typeof file.text === "function") return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error("backup_read_failed"));
    reader.readAsText(file);
  });
}
function saveNotesToStorage() {
  commitVaultSnapshot();
  updateStorageStat();
}
function saveTOTPToStorage() {
  commitVaultSnapshot();
}
function createVaultPayload() {
  const now = Date.now();
  return {
    schemaVersion: 2,
    notes: appState.notes.map((note) => ({
      ...note,
      tags: Array.isArray(note.tags) ? [...note.tags] : []
    })),
    totpAccounts: appState.totpAccounts.map((account) => ({
      ...account,
      password: account.password ?? "",
      digits: account.digits ?? 6,
      period: account.period ?? 30,
      algo: String(account.algo ?? "SHA1").toUpperCase().replace(/-/g, "")
    })),
    metadata: { createdAt: vaultMetadata.createdAt, updatedAt: now }
  };
}
function commitVaultSnapshot() {
  if (!vaultStore) {
    setVaultSaveStatus("save-failed");
    return null;
  }
  const write = vaultStore.commit(createVaultPayload());
  setVaultSaveStatus("pending");
  write.then(() => {
    if (vaultStore?.getStatus().state === "committed") setVaultSaveStatus("committed");
  }).catch((error) => {
    setVaultSaveStatus("save-failed");
    console.error("Vault commit failed; previous generation remains current:", error);
    showToast(t("save_failed"), "error");
  });
  return write;
}
async function verifyMasterPassword(password) {
  if (vaultStorageMode === "v2" && vaultAdapter) {
    try {
      const current = await vaultAdapter.getCurrent();
      await decryptVault(current, password);
      return true;
    } catch {
      return false;
    }
  }
  const legacy = await readLegacyVault(localStorage, { password });
  return legacy.state === "ready";
}
async function setMasterPassword(newPassword) {
  const adapter = vaultAdapter || new IndexedDBVaultAdapter();
  const store = new VaultStore({ adapter, password: newPassword });
  await store.loadCurrent();
  setVaultSaveStatus("pending");
  try {
    await store.commit(createVaultPayload());
    vaultAdapter = adapter;
    vaultStore = store;
    vaultStorageMode = "v2";
    completeLegacyMigration(localStorage);
    setVaultSaveStatus("committed");
  } catch (error) {
    setVaultSaveStatus("save-failed");
    throw error;
  }
}
var TRANSLATIONS = {
  en: {
    name: "English",
    flag: "🇺🇸",
    brand_badge: "2FA & CIPHER VAULT",
    tab_notepad: "Smart Notepad",
    tab_totp: "2FA Studio",
    zero_knowledge: "Zero-Knowledge",
    vault_unlocked: "Vault Unlocked",
    search_notes: "Search notes...",
    storage_used: "Storage used",
    storage_sub: "Plain Text • Browser Local Storage",
    note_title_placeholder: "Note title...",
    saved_status: "Saved",
    save_pending: "Saving…",
    save_saved: "Saved",
    save_failed: "Save failed",
    save_requires_encryption: "Set a master password before saving vault data.",
    backup_title: "Encrypted Backup",
    backup_export_btn: "Download Encrypted Backup",
    backup_choose_btn: "Choose .aeropad File",
    backup_restore_btn: "Restore Encrypted Backup",
    backup_password_label: "Backup master password",
    backup_password_ph: "Password used to create this backup",
    backup_status_default: "No encrypted backup recorded yet.",
    backup_last_export: "Last encrypted backup:",
    backup_file_selected: "Backup selected:",
    backup_exported: "Encrypted backup downloaded.",
    backup_restored: "Backup restored — vault locked for unlock.",
    backup_failed: "Backup operation failed — current vault was kept.",
    backup_restore_confirm: "Restore this encrypted backup? Current vault data will be replaced after password verification.",
    mode_edit: "Edit",
    mode_split: "Split",
    mode_preview: "Preview",
    export_file: "Export",
    copy_content: "Copy",
    note_content_placeholder: "Start typing your note... Markdown, to-do lists, seed phrases, or private security keys supported...",
    empty_notes_title: "No notes yet.",
    empty_notes_btn: "+ Create New Note",
    subtab_vault: "Live TOTP Vault",
    subtab_gen: "New 2FA (Secret & QR)",
    subtab_decoder: "Decode & Scan QR 2FA",
    vault_heading: "Two-Factor Authentication (TOTP)",
    vault_subheading: "Auto-refreshes via RFC 6238 TOTP. Runs 100% locally on Web Crypto API.",
    add_new_code_btn: "Add New Code",
    empty_totp_title: "No 2FA accounts in Vault",
    empty_totp_desc: 'Click "Add New Code" or switch to "New 2FA" / "Decode & Scan QR" to store 2FA accounts securely.',
    gen_heading: "Generate New Secret Key & 2FA QR",
    gen_subheading: "Generate high-entropy Base32 secret keys to enable two-factor authentication for your apps or services.",
    gen_issuer: "Issuer Name",
    gen_account: "Account / Email",
    gen_secret: "Secret Key (Base32)",
    gen_random_btn: "Generate New Random",
    gen_hash_algo: "Hash Algorithm",
    gen_period_digits: "Period & Digits",
    save_to_vault_btn: "Save Directly to Vault",
    no_qr_placeholder: "No QR Code yet.<br>Generate or enter a Secret Key.",
    download_qr_png: "Download QR PNG",
    copy_otp_link: "Copy OTP Link",
    dec_heading: "Decode QR Code & 2FA Key",
    dec_subheading: "Drag & drop QR code image, paste image from clipboard (Ctrl+V) or paste otpauth:// link to extract Secret Key & view real-time 6-digit code.",
    drop_title: "Drag & drop QR code image here",
    drop_subtitle: "or browse file / paste image from clipboard (Ctrl+V)",
    paste_prompt: "OR PASTE OTPAUTH URI / SECRET KEY",
    decode_now_btn: "Decode Now",
    dec_result_title: "2FA Account Information",
    dec_live_label: "REAL-TIME GENERATED 6-DIGIT CODE:",
    save_dec_to_vault: "Save This Account to Your Vault",
    modal_add_title: "Add New 2FA Account",
    cancel_btn: "Cancel",
    confirm_add_btn: "Add to Vault",
    modal_password_label: "Account Password (Optional)",
    modal_password_placeholder: "e.g. •••••••• (Leave empty if not needed)",
    gen_pass_quick: "Generate",
    toast_pass_copied: "Account password copied to clipboard!",
    word_unit: "words",
    char_unit: "characters",
    read_unit: "min read",
    toast_created_note: "New note created",
    toast_deleted_note: "Note deleted",
    toast_deleted_totp: "2FA account deleted",
    toast_copied_note: "Note content copied to clipboard",
    toast_secret_copied: "Secret key copied",
    toast_otp_copied: "OTP Auth link copied",
    toast_qr_downloaded: "QR Code downloaded as PNG",
    toast_code_copied: "2FA code copied:",
    toast_totp_added: "2FA account added to Vault",
    toast_qr_detected: "QR Code detected and decoded successfully!",
    toast_required_fields: "Please fill in all required fields (*)",
    toast_copy_failed: "Copy failed — please select the text and copy manually",
    toast_invalid_code: "No valid code available right now — wait for the next refresh",
    toast_invalid_secret: "Invalid secret key: use only letters A–Z and digits 2–7 (min 8 characters)",
    toast_not_an_image: "That file is not a readable image",
    toast_qr_read_failed: "Could not read the dropped file",
    toast_image_too_large: "Image too large (max 4096×4096) — use a smaller QR image",
    confirm_delete_note: "Delete this note permanently?",
    confirm_delete_totp: "Delete this 2FA account? The secret key will be lost forever!",
    lock_title: "Vault Locked",
    lock_subtitle: "Enter your master password to decrypt your data (AES-256-GCM, 100% local).",
    lock_password_ph: "Master password",
    lock_unlock_btn: "Unlock Vault",
    lock_wrong_pw: "Wrong password — try again",
    lock_error_generic: "Decryption failed — data may be corrupted",
    legacy_recovery_required: "Legacy storage needs recovery before it can be unlocked safely.",
    lock_failed: "Unable to lock safely because the latest save failed.",
    lock_no_recovery: "No recovery: the master password is the only key. If you forget it, the data is lost forever.",
    sec_title: "Vault Security",
    sec_status_encrypted: "🔒 Encrypted with AES-256-GCM (master password set)",
    sec_status_plain: "⚠️ Not encrypted — data is stored in plain text",
    sec_current_pw: "Current master password",
    sec_new_pw: "New master password",
    sec_confirm_pw: "Confirm new password",
    sec_set_btn: "Set Master Password & Encrypt",
    sec_change_btn: "Change Password",
    sec_remove_btn: "Remove Encryption",
    sec_remove_confirm: "Remove encryption? Your data will be stored in plain text again.",
    sec_lock_btn: "Lock Now",
    sec_pw_mismatch: "Passwords do not match",
    sec_pw_too_short: "Master password must be at least 8 characters",
    sec_encrypted_ok: "Vault encrypted — data is now AES-256-GCM at rest",
    sec_decrypted_ok: "Encryption removed — data is plain text again",
    storage_encrypted: "AES-256 Encrypted • Local Storage",
    storage_plain: "Plain Text • Not Encrypted",
    dec_issuer_ph: "Issuer name...",
    dec_account_ph: "Account / email...",
    dec_secret_ph: "Secret key (A–Z, 2–7)..."
  },
  vi: {
    name: "Tiếng Việt",
    flag: "🇻🇳",
    brand_badge: "2FA & KHO MẬT MÃ",
    tab_notepad: "Ghi Chú Thông Minh",
    tab_totp: "Xác Thực 2FA",
    zero_knowledge: "Zero-Knowledge",
    vault_unlocked: "Vault Đang Mở",
    search_notes: "Tìm ghi chú...",
    storage_used: "Dung lượng đã dùng",
    storage_sub: "Văn bản thuần • Lưu trữ cục bộ trên trình duyệt",
    note_title_placeholder: "Tiêu đề ghi chú...",
    saved_status: "Đã lưu",
    mode_edit: "Soạn thảo",
    mode_split: "Chia đôi",
    mode_preview: "Xem trước",
    export_file: "Xuất file",
    copy_content: "Sao chép",
    note_content_placeholder: "Bắt đầu gõ ghi chú của bạn... Hỗ trợ định dạng Markdown, danh sách to-do, seed phrases hoặc mã bảo mật bí mật...",
    empty_notes_title: "Chưa có ghi chú nào.",
    empty_notes_btn: "+ Tạo ghi chú mới",
    subtab_vault: "Kho Mã TOTP Trực Tiếp",
    subtab_gen: "Tạo Mới 2FA (Secret & QR)",
    subtab_decoder: "Giải Mã & Quét QR 2FA",
    vault_heading: "Mã Xác Thực 2 Bước (TOTP)",
    vault_subheading: "Tự động làm mới theo chuẩn RFC 6238 TOTP. Chạy hoàn toàn trên Web Crypto API cục bộ.",
    add_new_code_btn: "Thêm Mã Mới",
    empty_totp_title: "Chưa có mã 2FA nào trong Vault",
    empty_totp_desc: 'Hãy bấm "Thêm Mã Mới" hoặc sang tab "Tạo Mới 2FA" / "Giải Mã & Quét QR" để lưu tài khoản 2FA an toàn.',
    gen_heading: "Tạo Khóa Bí Mật & Mã QR 2FA Mới",
    gen_subheading: "Sinh khóa Base32 bảo mật cao để kích hoạt xác thực 2 bước cho dịch vụ hoặc ứng dụng của bạn.",
    gen_issuer: "Tên Đơn Vị Phát Hành",
    gen_account: "Tài Khoản / Email",
    gen_secret: "Khóa Bí Mật (Base32)",
    gen_random_btn: "Sinh ngẫu nhiên mới",
    gen_hash_algo: "Thuật toán Hash",
    gen_period_digits: "Chu kỳ & Chữ số",
    save_to_vault_btn: "Lưu Trực Tiếp Vào Vault",
    no_qr_placeholder: "Chưa có mã QR.<br>Hãy sinh hoặc nhập Secret Key.",
    download_qr_png: "Tải QR PNG",
    copy_otp_link: "Copy OTP Link",
    dec_heading: "Giải Mã Mã QR & Khóa 2FA",
    dec_subheading: "Kéo thả ảnh QR Code, dán ảnh từ clipboard (Ctrl+V) hoặc dán link otpauth:// để trích xuất Secret Key & xem mã 6 số tức thì.",
    drop_title: "Kéo thả ảnh mã QR vào đây",
    drop_subtitle: "hoặc nhấp để duyệt tệp / dán ảnh từ Clipboard (Ctrl+V)",
    paste_prompt: "HOẶC DÁN CHUỖI OTPAUTH / SECRET KEY",
    decode_now_btn: "Giải Mã Ngay",
    dec_result_title: "Thông Tin Tài Khoản 2FA",
    dec_live_label: "MÃ 6 SỐ THỜI GIAN THỰC ĐƯỢC TẠO RA:",
    save_dec_to_vault: "Lưu Tài Khoản Này Vào Vault Của Bạn",
    modal_add_title: "Thêm Mã 2FA Mới",
    cancel_btn: "Hủy",
    confirm_add_btn: "Thêm vào Vault",
    modal_password_label: "Mật khẩu tài khoản (Tùy chọn)",
    modal_password_placeholder: "vd: •••••••• (Để trống nếu không dùng)",
    gen_pass_quick: "Tạo tự động",
    toast_pass_copied: "Đã sao chép mật khẩu tài khoản!",
    word_unit: "từ",
    char_unit: "ký tự",
    read_unit: "phút đọc",
    toast_created_note: "Đã tạo ghi chú mới",
    toast_deleted_note: "Đã xóa ghi chú",
    toast_deleted_totp: "Đã xóa tài khoản 2FA",
    toast_copied_note: "Đã sao chép nội dung ghi chú",
    toast_secret_copied: "Đã sao chép khóa bí mật",
    toast_otp_copied: "Đã sao chép đường dẫn OTP Auth",
    toast_qr_downloaded: "Đã tải xuống ảnh mã QR",
    toast_code_copied: "Đã sao chép mã 2FA:",
    toast_totp_added: "Đã thêm tài khoản vào Vault",
    toast_qr_detected: "Đã phát hiện và giải mã mã QR thành công!",
    toast_required_fields: "Vui lòng điền đầy đủ các mục bắt buộc (*)",
    toast_copy_failed: "Sao chép thất bại — hãy bôi đen văn bản và copy thủ công",
    toast_invalid_code: "Chưa có mã hợp lệ — vui lòng đợi chu kỳ làm mới tiếp theo",
    toast_invalid_secret: "Khóa không hợp lệ: chỉ dùng chữ A–Z và số 2–7 (tối thiểu 8 ký tự)",
    toast_not_an_image: "Tệp không phải là ảnh hợp lệ",
    toast_qr_read_failed: "Không đọc được tệp đã thả",
    toast_image_too_large: "Ảnh quá lớn (tối đa 4096×4096) — dùng ảnh QR nhỏ hơn",
    confirm_delete_note: "Xóa vĩnh viễn ghi chú này?",
    confirm_delete_totp: "Xóa tài khoản 2FA này? Khóa bí mật sẽ mất vĩnh viễn!",
    lock_title: "Kho Mật Đã Khóa",
    lock_subtitle: "Nhập mật khẩu chính để giải mã dữ liệu (AES-256-GCM, 100% tại máy).",
    lock_password_ph: "Mật khẩu chính",
    lock_unlock_btn: "Mở Khóa Kho",
    lock_wrong_pw: "Sai mật khẩu — thử lại",
    lock_error_generic: "Giải mã thất bại — dữ liệu có thể đã hỏng",
    lock_no_recovery: "Không có khôi phục: mật khẩu chính là chìa khóa duy nhất. Quên là mất dữ liệu vĩnh viễn.",
    sec_title: "Bảo Mật Kho",
    sec_status_encrypted: "🔒 Đã mã hóa AES-256-GCM (đã đặt mật khẩu chính)",
    sec_status_plain: "⚠️ Chưa mã hóa — dữ liệu lưu dạng văn bản thuần",
    sec_current_pw: "Mật khẩu chính hiện tại",
    sec_new_pw: "Mật khẩu chính mới",
    sec_confirm_pw: "Xác nhận mật khẩu mới",
    sec_set_btn: "Đặt Mật Khẩu & Mã Hóa",
    sec_change_btn: "Đổi Mật Khẩu",
    sec_remove_btn: "Gỡ Mã Hóa",
    sec_remove_confirm: "Gỡ mã hóa? Dữ liệu sẽ lại lưu dạng văn bản thuần.",
    sec_lock_btn: "Khóa Ngay",
    sec_pw_mismatch: "Mật khẩu không khớp",
    sec_pw_too_short: "Mật khẩu chính phải dài tối thiểu 8 ký tự",
    sec_encrypted_ok: "Đã mã hóa kho — dữ liệu giờ được mã hóa AES-256-GCM",
    sec_decrypted_ok: "Đã gỡ mã hóa — dữ liệu trở lại văn bản thuần",
    storage_encrypted: "Mã hóa AES-256 • Lưu trữ cục bộ",
    storage_plain: "Văn bản thuần • Chưa mã hóa",
    dec_issuer_ph: "Tên đơn vị phát hành...",
    dec_account_ph: "Tài khoản / email...",
    dec_secret_ph: "Khóa bí mật (A–Z, 2–7)..."
  },
  zh: {
    name: "简体中文",
    flag: "🇨🇳",
    brand_badge: "2FA & 密码保险库",
    tab_notepad: "智能记事本",
    tab_totp: "2FA 工作室",
    zero_knowledge: "零知识加密",
    vault_unlocked: "保险库已解锁",
    search_notes: "搜索笔记...",
    storage_used: "已用存储",
    storage_sub: "明文存储 • 浏览器本地存储",
    note_title_placeholder: "笔记标题...",
    saved_status: "已保存",
    mode_edit: "编辑",
    mode_split: "分屏",
    mode_preview: "预览",
    export_file: "导出文件",
    copy_content: "复制内容",
    note_content_placeholder: "开始输入笔记... 支持 Markdown、待办清单、助记词或私密密钥...",
    empty_notes_title: "暂无笔记。",
    empty_notes_btn: "+ 创建新笔记",
    subtab_vault: "实时 TOTP 保险库",
    subtab_gen: "生成新 2FA (密钥与二维码)",
    subtab_decoder: "解码与扫描 2FA 二维码",
    vault_heading: "双重身份验证 (TOTP)",
    vault_subheading: "通过 RFC 6238 TOTP 自动刷新。100% 本地 Web Crypto API 运行。",
    add_new_code_btn: "添加新验证码",
    empty_totp_title: "保险库中暂无 2FA 账户",
    empty_totp_desc: "点击“添加新验证码”或切换至“生成新 2FA”/“解码与扫描”以安全保存 2FA 账户。",
    gen_heading: "生成新密钥与 2FA 二维码",
    gen_subheading: "生成高熵 Base32 密钥，为您的服务或应用启用双重身份验证。",
    gen_issuer: "发布机构名称",
    gen_account: "账户名称 / 邮箱",
    gen_secret: "密钥 (Base32)",
    gen_random_btn: "随机生成新密钥",
    gen_hash_algo: "哈希算法",
    gen_period_digits: "周期与位数",
    save_to_vault_btn: "直接保存至保险库",
    no_qr_placeholder: "暂无二维码。<br>请生成或输入密钥。",
    download_qr_png: "下载二维码 PNG",
    copy_otp_link: "复制 OTP 链接",
    dec_heading: "解码二维码与 2FA 密钥",
    dec_subheading: "拖放二维码图片、从剪贴板粘贴 (Ctrl+V) 或粘贴 otpauth:// 链接以提取密钥并查看实时 6 位代码。",
    drop_title: "将二维码图片拖放到此处",
    drop_subtitle: "或点击浏览文件 / 从剪贴板粘贴 (Ctrl+V)",
    paste_prompt: "或粘贴 OTPAUTH 链接 / 密钥",
    decode_now_btn: "立即解码",
    dec_result_title: "2FA 账户信息",
    dec_live_label: "实时生成的 6 位验证码：",
    save_dec_to_vault: "将此账户保存至您的保险库",
    modal_add_title: "添加新 2FA 账户",
    cancel_btn: "取消",
    confirm_add_btn: "添加至保险库",
    modal_password_label: "账户密码（可选）",
    modal_password_placeholder: "例如：••••••••（无需则留空）",
    gen_pass_quick: "随机生成",
    toast_pass_copied: "账户密码已复制到剪贴板！",
    word_unit: "字",
    char_unit: "字符",
    read_unit: "分钟阅读",
    toast_created_note: "已创建新笔记",
    toast_deleted_note: "已删除笔记",
    toast_deleted_totp: "已删除 2FA 账户",
    toast_copied_note: "笔记内容已复制到剪贴板",
    toast_secret_copied: "密钥已复制",
    toast_otp_copied: "OTP 链接已复制",
    toast_qr_downloaded: "二维码已下载为 PNG",
    toast_code_copied: "2FA 验证码已复制：",
    toast_totp_added: "已添加 2FA 账户至保险库",
    toast_qr_detected: "成功识别并解码二维码！",
    toast_required_fields: "请填写所有必填项（*）",
    toast_copy_failed: "复制失败 — 请手动选择文本复制",
    toast_invalid_code: "暂无有效验证码 — 请等待下一次刷新",
    toast_invalid_secret: "密钥无效：只能使用字母 A–Z 和数字 2–7（至少 8 个字符）",
    toast_not_an_image: "该文件不是可读取的图片",
    toast_qr_read_failed: "无法读取拖入的文件",
    toast_image_too_large: "图片过大（最大 4096×4096）— 请使用较小的二维码图片",
    confirm_delete_note: "永久删除此笔记？",
    confirm_delete_totp: "删除此 2FA 账户？密钥将永久丢失！",
    lock_title: "保险库已锁定",
    lock_subtitle: "输入主密码解密数据（AES-256-GCM，100% 本地）。",
    lock_password_ph: "主密码",
    lock_unlock_btn: "解锁保险库",
    lock_wrong_pw: "密码错误 — 请重试",
    lock_error_generic: "解密失败 — 数据可能已损坏",
    lock_no_recovery: "无法恢复：主密码是唯一密钥。忘记即永久丢失数据。",
    sec_title: "保险库安全",
    sec_status_encrypted: "🔒 已使用 AES-256-GCM 加密（已设置主密码）",
    sec_status_plain: "⚠️ 未加密 — 数据以明文存储",
    sec_current_pw: "当前主密码",
    sec_new_pw: "新主密码",
    sec_confirm_pw: "确认新密码",
    sec_set_btn: "设置主密码并加密",
    sec_change_btn: "更改密码",
    sec_remove_btn: "移除加密",
    sec_remove_confirm: "移除加密？数据将重新以明文存储。",
    sec_lock_btn: "立即锁定",
    sec_pw_mismatch: "两次输入的密码不一致",
    sec_pw_too_short: "主密码至少需要 8 个字符",
    sec_encrypted_ok: "保险库已加密 — 数据现已 AES-256-GCM 加密存储",
    sec_decrypted_ok: "已移除加密 — 数据恢复为明文",
    storage_encrypted: "AES-256 加密 • 本地存储",
    storage_plain: "明文 • 未加密",
    dec_issuer_ph: "发行方名称...",
    dec_account_ph: "账户 / 邮箱...",
    dec_secret_ph: "密钥 (A–Z, 2–7)..."
  },
  ko: {
    name: "한국어",
    flag: "🇰🇷",
    brand_badge: "2FA & 암호 금고",
    tab_notepad: "스마트 메모장",
    tab_totp: "2FA 스튜디오",
    zero_knowledge: "영지식 암호화",
    vault_unlocked: "금고 잠금해제됨",
    search_notes: "메모 검색...",
    storage_used: "사용된 용량",
    storage_sub: "일반 텍스트 • 브라우저 로컬 저장",
    note_title_placeholder: "메모 제목...",
    saved_status: "저장됨",
    mode_edit: "편집",
    mode_split: "분할",
    mode_preview: "미리보기",
    export_file: "내보내기",
    copy_content: "복사",
    note_content_placeholder: "메모를 작성하세요... 마크다운, 체크리스트, 시드 구문 또는 보안 키 지원...",
    empty_notes_title: "아직 메모가 없습니다.",
    empty_notes_btn: "+ 새 메모 작성",
    subtab_vault: "실시간 TOTP 금고",
    subtab_gen: "2FA 새로 만들기 (비밀키 & QR)",
    subtab_decoder: "2FA QR 디코드 & 스캔",
    vault_heading: "2단계 인증 (TOTP)",
    vault_subheading: "RFC 6238 TOTP 표준으로 자동 갱신됩니다. 로컬 Web Crypto API에서 100% 실행됩니다.",
    add_new_code_btn: "새 코드 추가",
    empty_totp_title: "금고에 2FA 계정이 없습니다",
    empty_totp_desc: '"새 코드 추가"를 누르거나 "2FA 새로 만들기" / "QR 디코드" 탭에서 계정을 저장하세요.',
    gen_heading: "새 비밀키 & 2FA QR 생성",
    gen_subheading: "서비스 또는 앱에 2단계 인증을 사용하도록 보안성 높은 Base32 키를 생성합니다.",
    gen_issuer: "발급자 이름",
    gen_account: "계정 이름 / 이메일",
    gen_secret: "비밀키 (Base32)",
    gen_random_btn: "새로 무작위 생성",
    gen_hash_algo: "해시 알고리즘",
    gen_period_digits: "주기 & 자릿수",
    save_to_vault_btn: "금고에 바로 저장",
    no_qr_placeholder: "QR 코드가 없습니다.<br>비밀키를 생성하거나 입력하세요.",
    download_qr_png: "QR PNG 다운로드",
    copy_otp_link: "OTP 링크 복사",
    dec_heading: "QR 코드 & 2FA 키 디코드",
    dec_subheading: "QR 코드 이미지를 드래그 앤 드롭하거나 클립보드에서 붙여넣어 비밀키를 추출하고 6자리 코드를 확인하세요.",
    drop_title: "QR 코드 이미지를 여기에 드래그 앤 드롭",
    drop_subtitle: "또는 파일 찾아보기 / 클립보드에서 붙여넣기 (Ctrl+V)",
    paste_prompt: "또는 OTPAUTH URI / 비밀키 붙여넣기",
    decode_now_btn: "지금 디코드",
    dec_result_title: "2FA 계정 정보",
    dec_live_label: "실시간 생성된 6자리 코드:",
    save_dec_to_vault: "이 계정을 금고에 저장",
    modal_add_title: "새 2FA 계정 추가",
    cancel_btn: "취소",
    confirm_add_btn: "금고에 추가",
    modal_password_label: "계정 비밀번호(선택사항)",
    modal_password_placeholder: "예: •••••••• (필요 없으면 비워둠)",
    gen_pass_quick: "자동 생성",
    toast_pass_copied: "계정 비밀번호가 클립보드에 복사되었습니다!",
    word_unit: "단어",
    char_unit: "글자",
    read_unit: "분 읽기",
    toast_created_note: "새 메모가 생성되었습니다",
    toast_deleted_note: "메모가 삭제되었습니다",
    toast_deleted_totp: "2FA 계정이 삭제되었습니다",
    toast_copied_note: "메모 내용이 클립보드에 복사되었습니다",
    toast_secret_copied: "비밀키가 복사되었습니다",
    toast_otp_copied: "OTP 링크가 복사되었습니다",
    toast_qr_downloaded: "QR 코드가 PNG로 다운로드되었습니다",
    toast_code_copied: "2FA 코드가 복사되었습니다:",
    toast_totp_added: "금고에 2FA 계정이 추가되었습니다",
    toast_qr_detected: "QR 코드가 감지되어 디코드되었습니다!",
    toast_required_fields: "모든 필수 항목(*)을 입력해 주세요",
    toast_copy_failed: "복사 실패 — 텍스트를 직접 선택하여 복사하세요",
    toast_invalid_code: "유효한 코드가 없습니다 — 다음 갱신까지 기다려 주세요",
    toast_invalid_secret: "잘못된 키: 문자 A–Z와 숫자 2–7만 사용 가능(최소 8자)",
    toast_not_an_image: "읽을 수 있는 이미지가 아닙니다",
    toast_qr_read_failed: "놓은 파일을 읽을 수 없습니다",
    toast_image_too_large: "이미지가 너무 큽니다(최대 4096×4096) — 더 작은 QR 이미지를 사용하세요",
    confirm_delete_note: "이 메모를 영구 삭제할까요?",
    confirm_delete_totp: "이 2FA 계정을 삭제할까요? 비밀키가 영구 삭제됩니다!",
    lock_title: "금고 잠김",
    lock_subtitle: "마스터 비밀번호를 입력하여 데이터를 복호화하세요 (AES-256-GCM, 100% 로컬).",
    lock_password_ph: "마스터 비밀번호",
    lock_unlock_btn: "금고 열기",
    lock_wrong_pw: "비밀번호가 틀렸습니다 — 다시 시도하세요",
    lock_error_generic: "복호화 실패 — 데이터가 손상되었을 수 있습니다",
    lock_no_recovery: "복구 불가: 마스터 비밀번호가 유일한 열쇠입니다. 잊어버리면 데이터를 영영 잃습니다.",
    sec_title: "금고 보안",
    sec_status_encrypted: "🔒 AES-256-GCM 암호화됨 (마스터 비밀번호 설정됨)",
    sec_status_plain: "⚠️ 암호화되지 않음 — 데이터가 일반 텍스트로 저장됨",
    sec_current_pw: "현재 마스터 비밀번호",
    sec_new_pw: "새 마스터 비밀번호",
    sec_confirm_pw: "새 비밀번호 확인",
    sec_set_btn: "마스터 비밀번호 설정 및 암호화",
    sec_change_btn: "비밀번호 변경",
    sec_remove_btn: "암호화 제거",
    sec_remove_confirm: "암호화를 제거할까요? 데이터가 다시 일반 텍스트로 저장됩니다.",
    sec_lock_btn: "지금 잠그기",
    sec_pw_mismatch: "비밀번호가 일치하지 않습니다",
    sec_pw_too_short: "마스터 비밀번호는 8자 이상이어야 합니다",
    sec_encrypted_ok: "금고 암호화 완료 — 데이터가 AES-256-GCM으로 저장됩니다",
    sec_decrypted_ok: "암호화 제거됨 — 데이터가 일반 텍스트로 저장됩니다",
    storage_encrypted: "AES-256 암호화 • 로컬 저장",
    storage_plain: "일반 텍스트 • 암호화 안 됨",
    dec_issuer_ph: "발급자 이름...",
    dec_account_ph: "계정 / 이메일...",
    dec_secret_ph: "비밀키 (A–Z, 2–7)..."
  },
  ja: {
    name: "日本語",
    flag: "🇯🇵",
    brand_badge: "2FA & 暗号ボールト",
    tab_notepad: "スマートノート",
    tab_totp: "2FA スタジオ",
    zero_knowledge: "ゼロ知識暗号",
    vault_unlocked: "ボールト解除中",
    search_notes: "ノートを検索...",
    storage_used: "使用済みストレージ",
    storage_sub: "平文 • ブラウザローカル保存",
    note_title_placeholder: "ノートのタイトル...",
    saved_status: "保存済み",
    mode_edit: "編集",
    mode_split: "分割",
    mode_preview: "プレビュー",
    export_file: "エクスポート",
    copy_content: "コピー",
    note_content_placeholder: "ノートを入力... Markdown、チェックリスト、シードフレーズ、秘密鍵に対応...",
    empty_notes_title: "ノートがありません。",
    empty_notes_btn: "+ 新規ノート作成",
    subtab_vault: "ライブ TOTP ボールト",
    subtab_gen: "新規 2FA (シークレット & QR)",
    subtab_decoder: "2FA QR デコード & スキャン",
    vault_heading: "2段階認証 (TOTP)",
    vault_subheading: "RFC 6238 TOTPで自動更新。ローカルのWeb Crypto APIで100%実行。",
    add_new_code_btn: "新規コード追加",
    empty_totp_title: "ボールトに2FAアカウントがありません",
    empty_totp_desc: "「新規コード追加」をクリックするか「新規2FA作成」/「QRデコード」タブで安全に保存してください。",
    gen_heading: "新規シークレットキー & 2FA QR生成",
    gen_subheading: "サービスやアプリで2要素認証を有効化するための安全なBase32キーを生成します。",
    gen_issuer: "発行者名",
    gen_account: "アカウント名 / メール",
    gen_secret: "シークレットキー (Base32)",
    gen_random_btn: "ランダム新規生成",
    gen_hash_algo: "ハッシュアルゴリズム",
    gen_period_digits: "周期 & 桁数",
    save_to_vault_btn: "ボールトに直接保存",
    no_qr_placeholder: "QRコードがありません。<br>キーを生成または入力してください。",
    download_qr_png: "QR PNGを保存",
    copy_otp_link: "OTPリンクをコピー",
    dec_heading: "QRコード & 2FAキーのデコード",
    dec_subheading: "QRコード画像をドラッグ＆ドロップするかクリップボードから貼り付けてキーを抽出します。",
    drop_title: "ここにQRコード画像をドラッグ＆ドロップ",
    drop_subtitle: "またはファイルを参照 / クリップボードから貼り付け (Ctrl+V)",
    paste_prompt: "または OTPAUTH URI / シークレットキーを貼り付け",
    decode_now_btn: "今すぐデコード",
    dec_result_title: "2FA アカウント情報",
    dec_live_label: "リアルタイム生成された6桁コード:",
    save_dec_to_vault: "このアカウントをボールトに保存",
    modal_add_title: "新規 2FA アカウント追加",
    cancel_btn: "キャンセル",
    confirm_add_btn: "ボールトに追加",
    modal_password_label: "アカウントパスワード（任意）",
    modal_password_placeholder: "例: •••••••• (不要な場合は空欄)",
    gen_pass_quick: "自動生成",
    toast_pass_copied: "アカウントパスワードをクリップボードにコピーしました！",
    word_unit: "単語",
    char_unit: "文字",
    read_unit: "分で読める",
    toast_created_note: "新規ノートを作成しました",
    toast_deleted_note: "ノートを削除しました",
    toast_deleted_totp: "2FAアカウントを削除しました",
    toast_copied_note: "ノート内容をコピーしました",
    toast_secret_copied: "シークレットキーをコピーしました",
    toast_otp_copied: "OTPリンクをコピーしました",
    toast_qr_downloaded: "QRコードをPNGで保存しました",
    toast_code_copied: "2FAコードをコピーしました:",
    toast_totp_added: "2FAアカウントをボールトに追加しました",
    toast_qr_detected: "QRコードを検出してデコードしました！",
    toast_required_fields: "すべての必須項目（*）を入力してください",
    toast_copy_failed: "コピーに失敗しました — テキストを選択して手動でコピーしてください",
    toast_invalid_code: "有効なコードがありません — 次の更新までお待ちください",
    toast_invalid_secret: "無効なキー: 英字 A–Z と数字 2–7 のみ使用可能（最小8文字）",
    toast_not_an_image: "読み込み可能な画像ではありません",
    toast_qr_read_failed: "ドロップされたファイルを読み込めません",
    toast_image_too_large: "画像が大きすぎます（最大 4096×4096）— より小さいQR画像を使用してください",
    confirm_delete_note: "このノートを完全に削除しますか？",
    confirm_delete_totp: "この2FAアカウントを削除しますか？シークレットキーは永久に失われます！",
    lock_title: "ボールトはロック中",
    lock_subtitle: "マスターパスワードを入力してデータを復号します（AES-256-GCM、100%ローカル）。",
    lock_password_ph: "マスターパスワード",
    lock_unlock_btn: "ボールトを解除",
    lock_wrong_pw: "パスワードが違います — もう一度お試しください",
    lock_error_generic: "復号に失敗 — データが破損している可能性があります",
    lock_no_recovery: "復元はできません：マスターパスワードが唯一の鍵です。忘れるとデータは永久に失われます。",
    sec_title: "ボールトセキュリティ",
    sec_status_encrypted: "🔒 AES-256-GCMで暗号化済み（マスターパスワード設定済み）",
    sec_status_plain: "⚠️ 未暗号化 — データは平文で保存されています",
    sec_current_pw: "現在のマスターパスワード",
    sec_new_pw: "新しいマスターパスワード",
    sec_confirm_pw: "新しいパスワードの確認",
    sec_set_btn: "マスターパスワードを設定して暗号化",
    sec_change_btn: "パスワード変更",
    sec_remove_btn: "暗号化を解除",
    sec_remove_confirm: "暗号化を解除しますか？データは再び平文で保存されます。",
    sec_lock_btn: "今すぐロック",
    sec_pw_mismatch: "パスワードが一致しません",
    sec_pw_too_short: "マスターパスワードは8文字以上必要です",
    sec_encrypted_ok: "ボールトを暗号化しました — データはAES-256-GCMで保存されます",
    sec_decrypted_ok: "暗号化を解除しました — データは平文に戻ります",
    storage_encrypted: "AES-256 暗号化 • ローカル保存",
    storage_plain: "平文 • 未暗号化",
    dec_issuer_ph: "発行者名...",
    dec_account_ph: "アカウント / メール...",
    dec_secret_ph: "シークレットキー (A–Z, 2–7)..."
  },
  es: {
    name: "Español",
    flag: "🇪🇸",
    brand_badge: "BÓVEDA 2FA & CIFRADO",
    tab_notepad: "Bloc de Notas",
    tab_totp: "Estudio 2FA",
    zero_knowledge: "Conocimiento Cero",
    vault_unlocked: "Bóveda Desbloqueada",
    search_notes: "Buscar notas...",
    storage_used: "Almacenamiento usado",
    storage_sub: "Texto sin cifrar • Almacenamiento local del navegador",
    note_title_placeholder: "Título de la nota...",
    saved_status: "Guardado",
    mode_edit: "Editar",
    mode_split: "Dividir",
    mode_preview: "Vista previa",
    export_file: "Exportar",
    copy_content: "Copiar",
    note_content_placeholder: "Escribe tu nota... Compatible con Markdown, listas de tareas, frases semilla o claves privadas...",
    empty_notes_title: "No hay notas aún.",
    empty_notes_btn: "+ Crear Nueva Nota",
    subtab_vault: "Bóveda TOTP en Vivo",
    subtab_gen: "Generar 2FA (Secreto y QR)",
    subtab_decoder: "Decodificar y Escanear QR 2FA",
    vault_heading: "Autenticación de Dos Factores (TOTP)",
    vault_subheading: "Se actualiza automáticamente mediante RFC 6238 TOTP. 100% local con Web Crypto API.",
    add_new_code_btn: "Agregar Código",
    empty_totp_title: "No hay cuentas 2FA en la Bóveda",
    empty_totp_desc: 'Haz clic en "Agregar Código" o ve a "Generar 2FA" / "Decodificar QR" para guardar cuentas de forma segura.',
    gen_heading: "Generar Clave Secreta y QR 2FA",
    gen_subheading: "Genera claves secretas Base32 de alta entropía para habilitar 2FA en tus servicios o aplicaciones.",
    gen_issuer: "Nombre del emisor",
    gen_account: "Cuenta / Correo",
    gen_secret: "Clave Secreta (Base32)",
    gen_random_btn: "Generar nuevo aleatorio",
    gen_hash_algo: "Algoritmo Hash",
    gen_period_digits: "Período y Dígitos",
    save_to_vault_btn: "Guardar en la Bóveda",
    no_qr_placeholder: "No hay código QR aún.<br>Genera o introduce una clave.",
    download_qr_png: "Descargar QR PNG",
    copy_otp_link: "Copiar Enlace OTP",
    dec_heading: "Decodificar Código QR y Clave 2FA",
    dec_subheading: "Arrastra y suelta la imagen QR, pégala desde el portapapeles (Ctrl+V) o pega el enlace otpauth:// para ver el código en tiempo real.",
    drop_title: "Arrastra y suelta la imagen QR aquí",
    drop_subtitle: "o buscar archivo / pegar imagen del portapapeles (Ctrl+V)",
    paste_prompt: "O PEGAR URI OTPAUTH / CLAVE SECRETA",
    decode_now_btn: "Decodificar Ahora",
    dec_result_title: "Información de la Cuenta 2FA",
    dec_live_label: "CÓDIGO DE 6 DÍGITOS GENERADO EN TIEMPO REAL:",
    save_dec_to_vault: "Guardar esta cuenta en la Bóveda",
    modal_add_title: "Agregar Cuenta 2FA",
    cancel_btn: "Cancelar",
    confirm_add_btn: "Agregar a la Bóveda",
    modal_password_label: "Contraseña de la cuenta (Opcional)",
    modal_password_placeholder: "ej. •••••••• (Dejar vacío si no es necesario)",
    gen_pass_quick: "Generar",
    toast_pass_copied: "¡Contraseña de la cuenta copiada al portapapeles!",
    word_unit: "palabras",
    char_unit: "caracteres",
    read_unit: "min de lectura",
    toast_created_note: "Nueva nota creada",
    toast_deleted_note: "Nota eliminada",
    toast_deleted_totp: "Cuenta 2FA eliminada",
    toast_copied_note: "Contenido copiado al portapapeles",
    toast_secret_copied: "Clave secreta copiada",
    toast_otp_copied: "Enlace OTP copiado",
    toast_qr_downloaded: "Código QR descargado como PNG",
    toast_code_copied: "Código 2FA copiado:",
    toast_totp_added: "Cuenta 2FA agregada a la Bóveda",
    toast_qr_detected: "¡Código QR detectado y decodificado!",
    toast_required_fields: "Por favor complete todos los campos obligatorios (*)",
    toast_copy_failed: "Error al copiar — selecciona el texto y cópialo manualmente",
    toast_invalid_code: "No hay un código válido — espera la siguiente actualización",
    toast_invalid_secret: "Clave inválida: usa solo letras A–Z y dígitos 2–7 (mín. 8 caracteres)",
    toast_not_an_image: "Ese archivo no es una imagen legible",
    toast_qr_read_failed: "No se pudo leer el archivo soltado",
    toast_image_too_large: "Imagen demasiado grande (máx. 4096×4096) — usa una imagen QR más pequeña",
    confirm_delete_note: "¿Eliminar esta nota permanentemente?",
    confirm_delete_totp: "¿Eliminar esta cuenta 2FA? ¡La clave secreta se perderá para siempre!",
    lock_title: "Bóveda Bloqueada",
    lock_subtitle: "Introduce tu contraseña maestra para descifrar tus datos (AES-256-GCM, 100% local).",
    lock_password_ph: "Contraseña maestra",
    lock_unlock_btn: "Desbloquear Bóveda",
    lock_wrong_pw: "Contraseña incorrecta — inténtalo de nuevo",
    lock_error_generic: "Fallo al descifrar — los datos pueden estar corruptos",
    lock_no_recovery: "Sin recuperación: la contraseña maestra es la única clave. Si la olvidas, pierdes los datos para siempre.",
    sec_title: "Seguridad de la Bóveda",
    sec_status_encrypted: "🔒 Cifrada con AES-256-GCM (contraseña maestra establecida)",
    sec_status_plain: "⚠️ Sin cifrar — los datos se guardan en texto plano",
    sec_current_pw: "Contraseña maestra actual",
    sec_new_pw: "Nueva contraseña maestra",
    sec_confirm_pw: "Confirmar nueva contraseña",
    sec_set_btn: "Establecer Contraseña y Cifrar",
    sec_change_btn: "Cambiar Contraseña",
    sec_remove_btn: "Quitar Cifrado",
    sec_remove_confirm: "¿Quitar el cifrado? Los datos volverán a guardarse en texto plano.",
    sec_lock_btn: "Bloquear Ahora",
    sec_pw_mismatch: "Las contraseñas no coinciden",
    sec_pw_too_short: "La contraseña maestra debe tener al menos 8 caracteres",
    sec_encrypted_ok: "Bóveda cifrada — los datos ahora se guardan con AES-256-GCM",
    sec_decrypted_ok: "Cifrado eliminado — los datos vuelven a texto plano",
    storage_encrypted: "Cifrado AES-256 • Almacenamiento Local",
    storage_plain: "Texto plano • Sin cifrar",
    dec_issuer_ph: "Nombre del emisor...",
    dec_account_ph: "Cuenta / correo...",
    dec_secret_ph: "Clave secreta (A–Z, 2–7)..."
  },
  id: {
    name: "Bahasa Indonesia",
    flag: "🇮🇩",
    brand_badge: "BRANKAS 2FA & CIPHER",
    tab_notepad: "Catatan Pintar",
    tab_totp: "Studio 2FA",
    zero_knowledge: "Nol-Pengetahuan",
    vault_unlocked: "Brankas Terbuka",
    search_notes: "Cari catatan...",
    storage_used: "Penyimpanan terpakai",
    storage_sub: "Teks polos • Penyimpanan lokal browser",
    note_title_placeholder: "Judul catatan...",
    saved_status: "Tersimpan",
    mode_edit: "Edit",
    mode_split: "Bagi",
    mode_preview: "Pratinjau",
    export_file: "Ekspor",
    copy_content: "Salin",
    note_content_placeholder: "Mulai mengetik catatan... Mendukung Markdown, daftar tugas, seed phrase, atau kunci keamanan privat...",
    empty_notes_title: "Belum ada catatan.",
    empty_notes_btn: "+ Buat Catatan Baru",
    subtab_vault: "Brankas TOTP Langsung",
    subtab_gen: "Buat 2FA Baru (Rahasia & QR)",
    subtab_decoder: "Dekode & Pindai QR 2FA",
    vault_heading: "Autentikasi Dua Faktor (TOTP)",
    vault_subheading: "Diperbarui otomatis via RFC 6238 TOTP. 100% berjalan lokal di Web Crypto API.",
    add_new_code_btn: "Tambah Kode Baru",
    empty_totp_title: "Belum ada akun 2FA di Brankas",
    empty_totp_desc: 'Klik "Tambah Kode Baru" atau buka tab "Buat 2FA" / "Dekode QR" untuk menyimpan akun dengan aman.',
    gen_heading: "Buat Kunci Rahasia & QR 2FA Baru",
    gen_subheading: "Hasilkan kunci rahasia Base32 berkekuatan tinggi untuk mengaktifkan autentikasi dua faktor.",
    gen_issuer: "Nama Penerbit",
    gen_account: "Nama Akun / Email",
    gen_secret: "Kunci Rahasia (Base32)",
    gen_random_btn: "Acak Baru",
    gen_hash_algo: "Algoritma Hash",
    gen_period_digits: "Periode & Digit",
    save_to_vault_btn: "Simpan ke Brankas",
    no_qr_placeholder: "Belum ada Kode QR.<br>Hasilkan atau masukkan Kunci Rahasia.",
    download_qr_png: "Unduh QR PNG",
    copy_otp_link: "Salin Tautan OTP",
    dec_heading: "Dekode Kode QR & Kunci 2FA",
    dec_subheading: "Tarik & lepas gambar kode QR, tempel gambar dari papan klip (Ctrl+V) atau tempel tautan otpauth:// untuk melihat kode 6 digit real-time.",
    drop_title: "Tarik & lepas gambar QR di sini",
    drop_subtitle: "atau telusuri file / tempel gambar dari papan klip (Ctrl+V)",
    paste_prompt: "ATAU TEMPEL OTPAUTH URI / KUNCI RAHASIA",
    decode_now_btn: "Dekode Sekarang",
    dec_result_title: "Informasi Akun 2FA",
    dec_live_label: "KODE 6 DIGIT DIHASILKAN SECARA REAL-TIME:",
    save_dec_to_vault: "Simpan Akun Ini ke Brankas Anda",
    modal_add_title: "Tambah Akun 2FA Baru",
    cancel_btn: "Batal",
    confirm_add_btn: "Tambah ke Brankas",
    modal_password_label: "Kata Sandi Akun (Opsional)",
    modal_password_placeholder: "cth: •••••••• (Biarkan kosong jika tidak perlu)",
    gen_pass_quick: "Hasilkan",
    toast_pass_copied: "Kata sandi akun disalin ke papan klip!",
    word_unit: "kata",
    char_unit: "karakter",
    read_unit: "mnt baca",
    toast_created_note: "Catatan baru dibuat",
    toast_deleted_note: "Catatan dihapus",
    toast_deleted_totp: "Akun 2FA dihapus",
    toast_copied_note: "Konten catatan disalin ke papan klip",
    toast_secret_copied: "Kunci rahasia disalin",
    toast_otp_copied: "Tautan OTP disalin",
    toast_qr_downloaded: "Kode QR diunduh sebagai PNG",
    toast_code_copied: "Kode 2FA disalin:",
    toast_totp_added: "Akun 2FA ditambahkan ke Brankas",
    toast_qr_detected: "Kode QR terdeteksi dan berhasil didekode!",
    toast_required_fields: "Harap isi semua bidang yang wajib diisi (*)",
    toast_copy_failed: "Gagal menyalin — pilih teks dan salin secara manual",
    toast_invalid_code: "Belum ada kode valid — tunggu pembaruan berikutnya",
    toast_invalid_secret: "Kunci tidak valid: hanya huruf A–Z dan angka 2–7 (min. 8 karakter)",
    toast_not_an_image: "File tersebut bukan gambar yang dapat dibaca",
    toast_qr_read_failed: "Tidak dapat membaca file yang dijatuhkan",
    toast_image_too_large: "Gambar terlalu besar (maks 4096×4096) — gunakan gambar QR lebih kecil",
    confirm_delete_note: "Hapus catatan ini secara permanen?",
    confirm_delete_totp: "Hapus akun 2FA ini? Kunci rahasia akan hilang selamanya!",
    lock_title: "Brankas Terkunci",
    lock_subtitle: "Masukkan kata sandi utama untuk mendekripsi data Anda (AES-256-GCM, 100% lokal).",
    lock_password_ph: "Kata sandi utama",
    lock_unlock_btn: "Buka Brankas",
    lock_wrong_pw: "Kata sandi salah — coba lagi",
    lock_error_generic: "Dekripsi gagal — data mungkin rusak",
    lock_no_recovery: "Tidak ada pemulihan: kata sandi utama adalah satu-satunya kunci. Lupa = data hilang selamanya.",
    sec_title: "Keamanan Brankas",
    sec_status_encrypted: "🔒 Terenkripsi AES-256-GCM (kata sandi utama telah diatur)",
    sec_status_plain: "⚠️ Belum terenkripsi — data disimpan sebagai teks polos",
    sec_current_pw: "Kata sandi utama saat ini",
    sec_new_pw: "Kata sandi utama baru",
    sec_confirm_pw: "Konfirmasi kata sandi baru",
    sec_set_btn: "Atur Kata Sandi & Enkripsi",
    sec_change_btn: "Ubah Kata Sandi",
    sec_remove_btn: "Hapus Enkripsi",
    sec_remove_confirm: "Hapus enkripsi? Data akan disimpan kembali sebagai teks polos.",
    sec_lock_btn: "Kunci Sekarang",
    sec_pw_mismatch: "Kata sandi tidak cocok",
    sec_pw_too_short: "Kata sandi utama minimal 8 karakter",
    sec_encrypted_ok: "Brankas terenkripsi — data kini disimpan dengan AES-256-GCM",
    sec_decrypted_ok: "Enkripsi dihapus — data kembali menjadi teks polos",
    storage_encrypted: "Terenkripsi AES-256 • Penyimpanan Lokal",
    storage_plain: "Teks polos • Tidak dienkripsi",
    dec_issuer_ph: "Nama penerbit...",
    dec_account_ph: "Akun / email...",
    dec_secret_ph: "Kunci rahasia (A–Z, 2–7)..."
  }
};
var DEFAULT_NOTES = [];
var DEFAULT_VAULT_ACCOUNTS = [];
var AUTO_LOCK_MS = 15 * 60 * 1e3;
var vaultStorageMode = "legacy";
var vaultAdapter = null;
var vaultStore = null;
var vaultMetadata = { createdAt: Date.now(), updatedAt: Date.now() };
var appInitialized = false;
var autoLockTimer = null;
var autoLockActivityBound = false;
var lastActivityAt = 0;
var lockInProgress = false;
var legacyRecoveryState = null;
var pendingBackupFile = null;
var noteSearchTimer = null;
var noteSearchQuery = "";
var appState = {
  // notes/totpAccounts stay empty here — bootVault() fills them after deciding
  // between the lock screen (encrypted envelope) and plain-text legacy mode
  notes: DEFAULT_NOTES,
  activeNoteId: null,
  totpAccounts: DEFAULT_VAULT_ACCOUNTS,
  theme: localStorage.getItem("aeropad_theme") || "dark",
  lang: localStorage.getItem("aeropad_lang") || "en",
  currentTab: "notepad",
  current2FASubtab: "vault",
  editorMode: "edit"
};
function t(key) {
  const langDict = TRANSLATIONS[appState.lang] || TRANSLATIONS.en;
  return langDict[key] || TRANSLATIONS.en[key] || key;
}
document.addEventListener("DOMContentLoaded", () => {
  initLockOverlay();
  bootVault();
});
function initAll() {
  if (appInitialized) {
    renderNotesList(noteSearchQuery);
    loadActiveNote();
    renderTOTPCards();
    updateStorageStat();
    updateEncryptionBadge();
    armAutoLock();
    return;
  }
  initLanguage();
  initTheme();
  initNavigation();
  initNotepad();
  initTOTPStudio();
  initDecoder();
  initSecurityUI();
  startGlobalTOTPTimer();
  updateStorageStat();
  updateEncryptionBadge();
  appInitialized = true;
  armAutoLock();
}
function applyVaultPayload(payload) {
  appState.notes = Array.isArray(payload?.notes) ? payload.notes : DEFAULT_NOTES;
  appState.totpAccounts = Array.isArray(payload?.totpAccounts) ? payload.totpAccounts : DEFAULT_VAULT_ACCOUNTS;
  vaultMetadata = payload?.metadata || vaultMetadata;
}
function clearTransientSecrets() {
  ["lockPasswordInput", "secNewPassword", "secConfirmPassword", "secCurrentPassword", "secNewPassword2", "secConfirmPassword2", "genSecret", "genPassword", "modalSecret", "modalPassword", "decPasswordInput", "decSecret", "backupRestorePassword"].forEach((id) => {
    const field = document.getElementById(id);
    if (field) field.value = "";
  });
  ["genSecret", "modalSecret", "decSecret"].forEach((id) => {
    const field = document.getElementById(id);
    if (field) field.type = "password";
  });
  ["toggleGenSecretVisibility", "toggleModalSecretVisibility", "toggleDecSecretVisibility"].forEach((id) => {
    const button = document.getElementById(id);
    button?.querySelector(".eye-open")?.classList.remove("hidden");
    button?.querySelector(".eye-closed")?.classList.add("hidden");
    button?.setAttribute("aria-label", "Show secret");
  });
  const fileInput = document.getElementById("backupFileInput");
  if (fileInput) fileInput.value = "";
  pendingBackupFile = null;
  document.querySelectorAll(".pass-masked-val").forEach((el) => {
    el.textContent = "••••••••••••";
  });
  if (typeof currentDecodedSecret !== "undefined") currentDecodedSecret = null;
  if (typeof currentDecodedItem !== "undefined") currentDecodedItem = null;
  const live = document.getElementById("decLiveCode");
  if (live) live.textContent = "------";
  lastTOTPWindows.clear();
  lastDecodedTOTPWindow = null;
}
function clearVaultSession() {
  if (autoLockTimer) clearInterval(autoLockTimer);
  autoLockTimer = null;
  vaultStore = null;
  appState.notes = [];
  appState.totpAccounts = [];
  appState.activeNoteId = null;
  clearTransientSecrets();
  closeAccessibleDialog(document.getElementById("securityModalBackdrop"));
  renderNotesList(noteSearchQuery);
  loadActiveNote();
  renderTOTPCards();
  updateStorageStat();
  showLockOverlay();
}
async function lockVaultSession() {
  if (lockInProgress) return;
  lockInProgress = true;
  const button = document.getElementById("secLockNowBtn");
  try {
    if (vaultStore) {
      if (vaultStore.getStatus().state === "save-failed") throw new Error("Vault has an uncommitted save failure");
      if (button) button.disabled = true;
      await vaultStore.flush();
      if (vaultStore.getStatus().state === "save-failed") throw new Error("Vault save failed before lock");
    }
    clearVaultSession();
  } catch (error) {
    setVaultSaveStatus("save-failed");
    console.error("Vault lock blocked because the latest save did not commit:", error);
    showToast(t("lock_failed"), "error");
    lastActivityAt = Date.now();
  } finally {
    if (button) button.disabled = false;
    lockInProgress = false;
  }
}
function armAutoLock() {
  if (!vaultStore) return;
  if (autoLockTimer) clearInterval(autoLockTimer);
  lastActivityAt = Date.now();
  if (!autoLockActivityBound) {
    const markActivity = () => {
      if (vaultStore) lastActivityAt = Date.now();
    };
    ["pointerdown", "keydown", "touchstart"].forEach((type) => document.addEventListener(type, markActivity, { passive: true }));
    document.addEventListener("visibilitychange", () => {
      if (!vaultStore || document.visibilityState !== "visible") return;
      if (Date.now() - lastActivityAt >= AUTO_LOCK_MS) lockVaultSession();
      else lastActivityAt = Date.now();
    });
    autoLockActivityBound = true;
  }
  autoLockTimer = setInterval(() => {
    if (vaultStore && Date.now() - lastActivityAt >= AUTO_LOCK_MS) lockVaultSession();
  }, 1e3);
}
async function bootVault() {
  try {
    vaultAdapter = new IndexedDBVaultAdapter();
    const current = await vaultAdapter.getCurrent();
    if (current) {
      vaultStorageMode = "v2";
      showLockOverlay();
      return;
    }
  } catch (error) {
    vaultAdapter = null;
    console.warn("IndexedDB vault unavailable; checking legacy storage:", error);
  }
  if (vaultIsEncrypted()) {
    showLockOverlay();
    return;
  }
  const legacy = await readLegacyVault(localStorage);
  if (legacy.state === "ready" || legacy.state === "empty") {
    applyVaultPayload(legacy.payload || { notes: DEFAULT_NOTES, totpAccounts: DEFAULT_VAULT_ACCOUNTS });
    initAll();
    return;
  }
  legacyRecoveryState = legacy;
  showLockOverlay();
}
async function unlockVaultWithPassword(password) {
  if (vaultStorageMode === "v2" && vaultAdapter) {
    const store = new VaultStore({ adapter: vaultAdapter, password });
    const current = await store.loadCurrent();
    if (!current) return false;
    try {
      const payload = await decryptVault(current, password);
      applyVaultPayload(payload);
      vaultStore = store;
      return true;
    } catch {
      return false;
    }
  }
  const legacy = await readLegacyVault(localStorage, { password });
  if (legacy.state !== "ready") return false;
  applyVaultPayload(legacy.payload);
  await setMasterPassword(password);
  return vaultStorageMode === "v2" && !!vaultStore;
}
function showLockOverlay() {
  const overlay = document.getElementById("lockOverlay");
  if (!overlay) {
    appState.notes = [];
    appState.totpAccounts = [];
    initAll();
    return;
  }
  overlay.classList.remove("hidden");
  overlay.setAttribute("aria-hidden", "false");
  const title = document.getElementById("lockTitle");
  if (title) title.textContent = t("lock_title");
  const subtitle = document.getElementById("lockSubtitle");
  if (subtitle) subtitle.textContent = t("lock_subtitle");
  const btn = document.getElementById("unlockVaultBtn");
  if (btn) btn.textContent = t("lock_unlock_btn");
  const recovery2 = document.getElementById("lockNoRecovery");
  if (recovery2) recovery2.textContent = t("lock_no_recovery");
  const errorEl = document.getElementById("lockError");
  if (errorEl && legacyRecoveryState) errorEl.textContent = t("legacy_recovery_required");
  const input = document.getElementById("lockPasswordInput");
  if (input) {
    input.placeholder = t("lock_password_ph");
    input.value = "";
    input.focus();
  }
}
async function attemptUnlock() {
  const input = document.getElementById("lockPasswordInput");
  const errorEl = document.getElementById("lockError");
  const btn = document.getElementById("unlockVaultBtn");
  const password = input ? input.value : "";
  if (!password || !btn || btn.disabled) return;
  btn.disabled = true;
  if (errorEl) errorEl.textContent = "";
  try {
    const ok = await unlockVaultWithPassword(password);
    if (!ok) {
      if (errorEl) errorEl.textContent = t("lock_wrong_pw");
      if (input) input.select();
      return;
    }
    const overlay = document.getElementById("lockOverlay");
    overlay?.classList.add("hidden");
    overlay?.setAttribute("aria-hidden", "true");
    if (input) input.value = "";
    legacyRecoveryState = null;
    initAll();
  } catch (err) {
    console.error("Unlock error:", err);
    if (errorEl) errorEl.textContent = t("lock_error_generic");
  } finally {
    btn.disabled = false;
  }
}
function updateEncryptionBadge() {
  const el = document.getElementById("storageModeLabel");
  if (el) el.textContent = vaultIsEncrypted() ? t("storage_encrypted") : t("storage_plain");
}
function createToastIcon(type) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width", "18");
  svg.setAttribute("height", "18");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", type === "error" ? "#F43F5E" : "#00F2FE");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("aria-hidden", "true");
  const shape = type === "error" ? document.createElementNS(svg.namespaceURI, "circle") : document.createElementNS(svg.namespaceURI, "polyline");
  if (type === "error") {
    shape.setAttribute("cx", "12");
    shape.setAttribute("cy", "12");
    shape.setAttribute("r", "10");
    const lineA = document.createElementNS(svg.namespaceURI, "line");
    lineA.setAttribute("x1", "15");
    lineA.setAttribute("y1", "9");
    lineA.setAttribute("x2", "9");
    lineA.setAttribute("y2", "15");
    const lineB = document.createElementNS(svg.namespaceURI, "line");
    lineB.setAttribute("x1", "9");
    lineB.setAttribute("y1", "9");
    lineB.setAttribute("x2", "15");
    lineB.setAttribute("y2", "15");
    svg.append(shape, lineA, lineB);
  } else {
    shape.setAttribute("points", "20 6 9 17 4 12");
    svg.append(shape);
  }
  return svg;
}
function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = "toast-item glass-panel";
  const messageEl = document.createElement("span");
  messageEl.textContent = String(message ?? "");
  toast.append(createToastIcon(type), messageEl);
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 2600);
}
var DIALOG_FOCUSABLE_SELECTOR = 'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href], [tabindex]:not([tabindex="-1"])';
function getDialogFocusables(dialog) {
  return [...dialog?.querySelectorAll(DIALOG_FOCUSABLE_SELECTOR) || []].filter((el) => !el.closest(".hidden") && el.getAttribute("aria-hidden") !== "true");
}
function closeAccessibleDialog(backdrop) {
  if (!backdrop) return;
  backdrop.classList.add("hidden");
  backdrop.setAttribute("aria-hidden", "true");
  const returnFocus = backdrop._aeroReturnFocus;
  backdrop._aeroReturnFocus = null;
  if (returnFocus && typeof returnFocus.focus === "function") returnFocus.focus();
}
function openAccessibleDialog(backdrop, trigger, initialFocusId) {
  if (!backdrop) return;
  backdrop._aeroReturnFocus = trigger || document.activeElement;
  backdrop.classList.remove("hidden");
  backdrop.setAttribute("aria-hidden", "false");
  const dialog = backdrop.querySelector('[role="dialog"]');
  const initial = initialFocusId ? document.getElementById(initialFocusId) : null;
  const target = initial && !initial.closest(".hidden") ? initial : getDialogFocusables(dialog)[0];
  target?.focus();
}
function initAccessibleDialog(backdrop) {
  if (!backdrop) return;
  backdrop.setAttribute("aria-hidden", backdrop.classList.contains("hidden") ? "true" : "false");
  backdrop.addEventListener("keydown", (event) => {
    if (backdrop.classList.contains("hidden")) return;
    const dialog = backdrop.querySelector('[role="dialog"]');
    if (event.key === "Escape") {
      event.preventDefault();
      closeAccessibleDialog(backdrop);
      return;
    }
    if (event.key !== "Tab" || !dialog || !dialog.contains(document.activeElement)) return;
    const focusables = getDialogFocusables(dialog);
    if (!focusables.length) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (focusables.length === 1 || event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
}
function initLanguage() {
  const wrap = document.getElementById("langDropdownWrap");
  const btn = document.getElementById("langToggleBtn");
  const menu = document.getElementById("langMenu");
  btn?.addEventListener("click", (e) => {
    e.stopPropagation();
    wrap?.classList.toggle("open");
    menu?.classList.toggle("show");
  });
  document.addEventListener("click", (e) => {
    if (!wrap?.contains(e.target)) {
      wrap?.classList.remove("open");
      menu?.classList.remove("show");
    }
  });
  menu?.querySelectorAll(".lang-opt").forEach((opt) => {
    opt.addEventListener("click", (e) => {
      e.stopPropagation();
      const selectedLang = opt.getAttribute("data-lang");
      if (selectedLang) {
        applyLanguage(selectedLang);
      }
      wrap?.classList.remove("open");
      menu?.classList.remove("show");
    });
  });
  applyLanguage(appState.lang);
}
function applyLanguage(lang) {
  if (!TRANSLATIONS[lang]) lang = "en";
  appState.lang = lang;
  localStorage.setItem("aeropad_lang", lang);
  const currentLabel = document.getElementById("currentLangLabel");
  if (currentLabel) {
    currentLabel.textContent = TRANSLATIONS[lang].name;
  }
  document.querySelectorAll("#langMenu .lang-opt").forEach((opt) => {
    opt.classList.toggle("active", opt.dataset.lang === lang);
  });
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (key && TRANSLATIONS[lang][key]) {
      el.textContent = TRANSLATIONS[lang][key];
    }
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    if (key && TRANSLATIONS[lang][key]) {
      el.setAttribute("placeholder", TRANSLATIONS[lang][key]);
    }
  });
  renderNotesList(noteSearchQuery);
  renderTOTPCards();
  updateWordCounts();
  renderQRCode();
  updateEncryptionBadge();
}
function initTheme() {
  const root = document.documentElement;
  if (appState.theme === "light") {
    root.classList.remove("dark");
    root.classList.add("light");
  } else {
    root.classList.remove("light");
    root.classList.add("dark");
  }
  document.getElementById("themeToggle")?.addEventListener("click", () => {
    if (root.classList.contains("dark")) {
      root.classList.remove("dark");
      root.classList.add("light");
      appState.theme = "light";
    } else {
      root.classList.remove("light");
      root.classList.add("dark");
      appState.theme = "dark";
    }
    localStorage.setItem("aeropad_theme", appState.theme);
    renderQRCode();
  });
}
function initNavigation() {
  document.querySelectorAll(".nav-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-pill").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const tabId = btn.dataset.tab;
      const targetPane = document.getElementById(`tab-${tabId}`);
      if (targetPane) targetPane.classList.add("active");
      appState.currentTab = tabId;
    });
  });
  document.querySelectorAll(".totp-subpill").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".totp-subpill").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".totp-subpane").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const subtab = btn.dataset.subtab;
      const targetSubpane = document.getElementById(`subtab-${subtab}`);
      if (targetSubpane) targetSubpane.classList.add("active");
      appState.current2FASubtab = subtab;
      if (subtab === "generator") {
        renderQRCode();
      }
    });
  });
  const vaultBtn = document.getElementById("vaultLockBtn");
  vaultBtn?.addEventListener("click", openSecurityModal);
}
function initLockOverlay() {
  document.getElementById("unlockVaultBtn")?.addEventListener("click", attemptUnlock);
  document.getElementById("lockPasswordInput")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") attemptUnlock();
  });
}
async function exportEncryptedBackup() {
  const button = document.getElementById("exportBackupBtn");
  if (!vaultStore || button?.disabled) {
    setBackupStatus("backup-error", t("backup_failed"));
    return;
  }
  if (vaultStore.getStatus().state === "save-failed") {
    setBackupStatus("backup-error", t("backup_failed"));
    showToast(t("backup_failed"), "error");
    return;
  }
  if (button) button.disabled = true;
  try {
    const current = await vaultStore.flush();
    if (!current) throw new Error("backup_no_current_record");
    const backup = await createBackup(current);
    const blob = new Blob([serializeBackup(backup)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `aeropad-backup-${(/* @__PURE__ */ new Date()).toISOString().slice(0, 10)}.aeropad`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL?.(url);
    const timestamp = Date.now();
    localStorage.setItem("aeropad_last_backup_at", String(timestamp));
    setBackupStatus("backup-ready", `${t("backup_last_export")} ${new Date(timestamp).toLocaleString()}`);
    showToast(t("backup_exported"));
  } catch (error) {
    setBackupStatus("backup-error", t("backup_failed"));
    console.error("Encrypted backup export failed:", error);
    showToast(t("backup_failed"), "error");
  } finally {
    if (button) button.disabled = false;
  }
}
function syncBackupRestoreButton() {
  const password = document.getElementById("backupRestorePassword")?.value || "";
  const button = document.getElementById("restoreBackupBtn");
  if (button) button.disabled = !pendingBackupFile || password.length === 0;
}
async function restoreEncryptedBackup() {
  const password = document.getElementById("backupRestorePassword")?.value || "";
  const button = document.getElementById("restoreBackupBtn");
  if (!pendingBackupFile || !password || !vaultStore || !vaultAdapter || button?.disabled) return;
  if (!window.confirm(t("backup_restore_confirm"))) return;
  button.disabled = true;
  try {
    if (vaultStore.getStatus().state === "save-failed") throw new Error("backup_save_failed");
    await vaultStore.flush();
    await restoreBackup(vaultAdapter, await readBackupFile(pendingBackupFile), password);
    clearVaultSession();
    showToast(t("backup_restored"));
  } catch (error) {
    setBackupStatus("backup-error", t("backup_failed"));
    console.error("Encrypted backup restore failed:", error);
    showToast(t("backup_failed"), "error");
    syncBackupRestoreButton();
  } finally {
    if (button && button.disabled) button.disabled = false;
    syncBackupRestoreButton();
  }
}
function initSecurityUI() {
  const secBackdrop = document.getElementById("securityModalBackdrop");
  if (!secBackdrop) return;
  initAccessibleDialog(secBackdrop);
  const closeSec = () => closeAccessibleDialog(secBackdrop);
  document.getElementById("closeSecurityModalBtn")?.addEventListener("click", closeSec);
  secBackdrop.addEventListener("click", (e) => {
    if (e.target === secBackdrop) closeSec();
  });
  document.getElementById("secSetPasswordBtn")?.addEventListener("click", async () => {
    const pw = document.getElementById("secNewPassword")?.value || "";
    const confirmPw = document.getElementById("secConfirmPassword")?.value || "";
    if (pw.length < 8) return showToast(t("sec_pw_too_short"), "error");
    if (pw !== confirmPw) return showToast(t("sec_pw_mismatch"), "error");
    try {
      await setMasterPassword(pw);
      showToast(t("sec_encrypted_ok"));
      updateEncryptionBadge();
      updateStorageStat();
      armAutoLock();
      closeSec();
    } catch (err) {
      console.error("Encryption setup failed:", err);
      showToast(t("lock_error_generic"), "error");
    }
  });
  document.getElementById("secChangePasswordBtn")?.addEventListener("click", async () => {
    const cur = document.getElementById("secCurrentPassword")?.value || "";
    const pw = document.getElementById("secNewPassword2")?.value || "";
    const confirmPw = document.getElementById("secConfirmPassword2")?.value || "";
    if (pw.length < 8) return showToast(t("sec_pw_too_short"), "error");
    if (pw !== confirmPw) return showToast(t("sec_pw_mismatch"), "error");
    if (!await verifyMasterPassword(cur)) return showToast(t("lock_wrong_pw"), "error");
    try {
      await setMasterPassword(pw);
      showToast(t("sec_encrypted_ok"));
      updateEncryptionBadge();
      armAutoLock();
      closeSec();
    } catch (err) {
      console.error("Password change failed:", err);
      showToast(t("lock_error_generic"), "error");
    }
  });
  document.getElementById("secRemovePasswordBtn")?.addEventListener("click", () => {
    showToast(t("save_requires_encryption"), "error");
  });
  document.getElementById("secLockNowBtn")?.addEventListener("click", () => {
    lockVaultSession();
  });
  document.getElementById("exportBackupBtn")?.addEventListener("click", exportEncryptedBackup);
  document.getElementById("chooseBackupFileBtn")?.addEventListener("click", () => document.getElementById("backupFileInput")?.click());
  document.getElementById("backupFileInput")?.addEventListener("change", (event) => {
    pendingBackupFile = event.target.files?.[0] || null;
    const name = document.getElementById("backupFileName");
    if (name) name.textContent = pendingBackupFile ? `${t("backup_file_selected")} ${pendingBackupFile.name}` : "";
    syncBackupRestoreButton();
  });
  document.getElementById("backupRestorePassword")?.addEventListener("input", syncBackupRestoreButton);
  document.getElementById("restoreBackupBtn")?.addEventListener("click", restoreEncryptedBackup);
}
function openSecurityModal(event) {
  const backdrop = document.getElementById("securityModalBackdrop");
  if (!backdrop) return;
  const encrypted = vaultIsEncrypted();
  document.getElementById("secStatusEncrypted")?.classList.toggle("hidden", !encrypted);
  document.getElementById("secStatusPlain")?.classList.toggle("hidden", encrypted);
  document.getElementById("secSetupSection")?.classList.toggle("hidden", encrypted);
  document.getElementById("secManageSection")?.classList.toggle("hidden", !encrypted);
  document.getElementById("secRemovePasswordBtn")?.classList.add("hidden");
  ["secNewPassword", "secConfirmPassword", "secCurrentPassword", "secNewPassword2", "secConfirmPassword2"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });
  pendingBackupFile = null;
  const backupFileInput = document.getElementById("backupFileInput");
  if (backupFileInput) backupFileInput.value = "";
  const backupFileName = document.getElementById("backupFileName");
  if (backupFileName) backupFileName.textContent = "";
  const backupPassword = document.getElementById("backupRestorePassword");
  if (backupPassword) backupPassword.value = "";
  syncBackupRestoreButton();
  updateBackupStatus();
  openAccessibleDialog(backdrop, event?.currentTarget || document.getElementById("vaultLockBtn"), encrypted ? "secCurrentPassword" : "secNewPassword");
}
function initNotepad() {
  if (appState.notes.length > 0) {
    appState.activeNoteId = appState.notes[0].id;
  }
  renderNotesList();
  loadActiveNote();
  const titleInput = document.getElementById("noteTitle");
  const contentInput = document.getElementById("noteContent");
  titleInput?.addEventListener("input", autoSaveNote);
  contentInput?.addEventListener("input", () => {
    autoSaveNote();
    updateWordCounts();
    if (appState.editorMode !== "edit") {
      renderMarkdownPreview();
    }
  });
  document.getElementById("newNoteBtn")?.addEventListener("click", createNewNote);
  document.getElementById("deleteNoteBtn")?.addEventListener("click", () => {
    if (appState.notes.length === 0) return;
    if (!window.confirm(t("confirm_delete_note"))) return;
    appState.notes = appState.notes.filter((n) => n.id !== appState.activeNoteId);
    appState.activeNoteId = appState.notes.length > 0 ? appState.notes[0].id : null;
    saveNotesToStorage();
    renderNotesList();
    loadActiveNote();
    showToast(t("toast_deleted_note"));
  });
  document.getElementById("noteSearch")?.addEventListener("input", (e) => {
    noteSearchQuery = e.target.value;
    clearTimeout(noteSearchTimer);
    noteSearchTimer = setTimeout(() => renderNotesList(noteSearchQuery), NOTE_SEARCH_DEBOUNCE_MS);
  });
  document.querySelectorAll(".editor-mode-toggle button").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".editor-mode-toggle button").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const mode = btn.dataset.mode;
      appState.editorMode = mode;
      const raw = document.getElementById("noteContent");
      const prev = document.getElementById("notePreview");
      if (mode === "edit") {
        raw.classList.remove("hidden");
        prev.classList.add("hidden");
      } else if (mode === "preview") {
        raw.classList.add("hidden");
        prev.classList.remove("hidden");
        renderMarkdownPreview();
      } else if (mode === "split") {
        raw.classList.remove("hidden");
        prev.classList.remove("hidden");
        renderMarkdownPreview();
      }
    });
  });
  document.querySelectorAll(".editor-toolbar button[data-format]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const format = btn.dataset.format;
      insertFormatting(format);
    });
  });
  document.getElementById("copyNoteContent")?.addEventListener("click", async () => {
    const note = appState.notes.find((n) => n.id === appState.activeNoteId);
    if (!note) return;
    const ok = await copyTextToClipboard(`${note.title}

${note.content}`);
    if (ok) showToast(t("toast_copied_note"));
    else showToast(t("toast_copy_failed"), "error");
  });
  const exportBtn = document.getElementById("exportBtn");
  const exportMenu = document.getElementById("exportMenu");
  exportBtn?.addEventListener("click", (e) => {
    e.stopPropagation();
    exportMenu.classList.toggle("show");
  });
  document.addEventListener("click", () => exportMenu?.classList.remove("show"));
  exportMenu?.querySelectorAll("button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const format = btn.dataset.export;
      exportNoteFile(format);
    });
  });
}
function createNewNote() {
  const newNote = {
    id: generateId("note"),
    title: t("note_title_placeholder").replace("...", ""),
    content: "",
    updatedAt: Date.now()
  };
  appState.notes.unshift(newNote);
  appState.activeNoteId = newNote.id;
  saveNotesToStorage();
  renderNotesList();
  loadActiveNote();
  const titleInput = document.getElementById("noteTitle");
  if (titleInput) {
    titleInput.focus();
    titleInput.select();
  }
  showToast(t("toast_created_note"));
}
function renderNotesList(filterQuery = "") {
  const list = document.getElementById("notesList");
  if (!list) return;
  list.innerHTML = "";
  const filtered = searchNotes(appState.notes, filterQuery);
  if (filtered.length === 0) {
    list.innerHTML = `
      <div class="empty-state-notes">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:36px;height:36px;opacity:0.4"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
        <p>${t("empty_notes_title")}</p>
        <button class="btn-primary-gradient btn-sm" id="emptyCreateNoteBtn" style="margin-top:4px">${t("empty_notes_btn")}</button>
      </div>
    `;
    document.getElementById("emptyCreateNoteBtn")?.addEventListener("click", createNewNote);
    return;
  }
  filtered.forEach((note) => {
    const item = document.createElement("div");
    item.className = `note-item ${note.id === appState.activeNoteId ? "active" : ""}`;
    item.setAttribute("tabindex", "0");
    item.setAttribute("role", "button");
    item.setAttribute("aria-label", `Open note: ${note.title || "Untitled"}`);
    const timeAgo = formatTimeAgo(note.updatedAt);
    const snippet = note.content.slice(0, 45).replace(/[#*`\n]/g, " ") || "...";
    item.innerHTML = `
      <div class="note-item-title">${escapeHTML(note.title || "Untitled")}</div>
      <div class="note-item-snippet">${escapeHTML(snippet)}</div>
      <div class="note-item-time">${timeAgo}</div>
    `;
    const openNote = () => {
      appState.activeNoteId = note.id;
      renderNotesList(filterQuery);
      loadActiveNote();
    };
    item.addEventListener("click", openNote);
    item.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      e.preventDefault();
      openNote();
    });
    list.appendChild(item);
  });
}
function loadActiveNote() {
  const note = appState.notes.find((n) => n.id === appState.activeNoteId);
  const titleInput = document.getElementById("noteTitle");
  const contentInput = document.getElementById("noteContent");
  if (!note) {
    if (titleInput) titleInput.value = "";
    if (contentInput) contentInput.value = "";
    updateWordCounts();
    renderMarkdownPreview();
    return;
  }
  if (titleInput) titleInput.value = note.title;
  if (contentInput) contentInput.value = note.content;
  updateWordCounts();
  renderMarkdownPreview();
}
function autoSaveNote() {
  if (appState.notes.length === 0) {
    const newNote = {
      id: generateId("note"),
      title: document.getElementById("noteTitle").value || "Note",
      content: document.getElementById("noteContent").value || "",
      updatedAt: Date.now()
    };
    appState.notes.push(newNote);
    appState.activeNoteId = newNote.id;
  } else {
    const note = appState.notes.find((n) => n.id === appState.activeNoteId);
    if (!note) return;
    note.title = document.getElementById("noteTitle").value;
    note.content = document.getElementById("noteContent").value;
    note.updatedAt = Date.now();
  }
  saveNotesToStorage();
  renderNotesList();
  const indicator = document.getElementById("saveIndicator");
  if (indicator) indicator.style.opacity = "1";
}
function updateWordCounts() {
  const contentEl = document.getElementById("noteContent");
  const text = contentEl ? contentEl.value : "";
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;
  const chars = text.length;
  const readMinutes = Math.max(1, Math.ceil(words / 200));
  const wordEl = document.getElementById("wordCount");
  const charEl = document.getElementById("charCount");
  const readEl = document.getElementById("readTime");
  if (wordEl) wordEl.textContent = `${words} ${t("word_unit")}`;
  if (charEl) charEl.textContent = `${chars} ${t("char_unit")}`;
  if (readEl) readEl.textContent = `${readMinutes} ${t("read_unit")}`;
}
function renderMarkdownPreview() {
  const contentEl = document.getElementById("noteContent");
  const text = contentEl ? contentEl.value : "";
  const preview = document.getElementById("notePreview");
  if (!preview) return;
  let html = escapeHTML(text).replace(/^# (.*$)/gim, "<h1>$1</h1>").replace(/^## (.*$)/gim, "<h2>$1</h2>").replace(/^### (.*$)/gim, "<h3>$1</h3>").replace(/\*\*(.*?)\*\*/gim, "<b>$1</b>").replace(/\*(.*?)\*/gim, "<i>$1</i>").replace(/`([^`]+)`/gim, "<code>$1</code>").replace(/^- \[(x|X)\] (.*$)/gim, '<div class="check-item checked"><input type="checkbox" checked disabled> $2</div>').replace(/^- \[ \] (.*$)/gim, '<div class="check-item"><input type="checkbox" disabled> $2</div>').replace(/^- (.*$)/gim, "<li>$1</li>").replace(/^\> (.*$)/gim, "<blockquote>$1</blockquote>").replace(/\n\n/gim, "<br><br>");
  preview.innerHTML = html || `<p style="color:var(--text-muted)">${t("empty_notes_title")}</p>`;
}
function insertFormatting(type) {
  const textarea = document.getElementById("noteContent");
  if (!textarea) return;
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const selText = textarea.value.substring(start, end);
  let insert = "";
  switch (type) {
    case "bold":
      insert = `**${selText || "bold text"}**`;
      break;
    case "italic":
      insert = `*${selText || "italic text"}*`;
      break;
    case "heading":
      insert = `
## ${selText || "Heading"}
`;
      break;
    case "code":
      insert = `\`${selText || "code"}\``;
      break;
    case "quote":
      insert = `
> ${selText || "Quote"}
`;
      break;
    case "list":
      insert = `
- ${selText || "List item"}`;
      break;
    case "check":
      insert = `
- [ ] ${selText || "To-do item"}`;
      break;
  }
  textarea.setRangeText(insert, start, end, "end");
  autoSaveNote();
  updateWordCounts();
  if (appState.editorMode !== "edit") renderMarkdownPreview();
}
function exportNoteFile(type) {
  const note = appState.notes.find((n) => n.id === appState.activeNoteId);
  if (!note) {
    showToast(t("empty_notes_title"), "error");
    return;
  }
  let content = "";
  let filename = `${(note.title || "note").replace(/\s+/g, "_")}`;
  let mimeType = "text/plain";
  if (type === "md") {
    content = `# ${note.title}

${note.content}`;
    filename += ".md";
    mimeType = "text/markdown";
  } else if (type === "txt") {
    content = `${note.title}

${note.content}`;
    filename += ".txt";
    mimeType = "text/plain";
  } else if (type === "json") {
    content = JSON.stringify(note, null, 2);
    filename += "-backup.json";
    mimeType = "application/json";
  }
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Exported: ${filename}`);
}
function updateStorageStat() {
  const jsonStr = JSON.stringify(appState);
  const bytes2 = new Blob([jsonStr]).size;
  const kb = (bytes2 / 1024).toFixed(1);
  const el = document.getElementById("storageUsage");
  if (el) el.textContent = `${kb} KB`;
  const bar = document.getElementById("storageProgressBar");
  if (bar) bar.style.width = `${Math.min(100, bytes2 / (5 * 1024 * 1024) * 100).toFixed(1)}%`;
}
function initTOTPStudio() {
  renderTOTPCards();
  initTOTPGenerator();
}
function secureRandomInt(max) {
  const limit = Math.floor(4294967296 / max) * max;
  const buf = new Uint32Array(1);
  do {
    window.crypto.getRandomValues(buf);
  } while (buf[0] >= limit);
  return buf[0] % max;
}
function generateRandomPassword(length = 16) {
  if (length < 4) length = 4;
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const digits = "23456789";
  const symbols = "!@#$%^&*()_+~|}{[]:;?><,.-=";
  const all = upper + lower + digits + symbols;
  const chars = [
    upper[secureRandomInt(upper.length)],
    lower[secureRandomInt(lower.length)],
    digits[secureRandomInt(digits.length)],
    symbols[secureRandomInt(symbols.length)]
  ];
  for (let i = 4; i < length; i++) {
    chars.push(all[secureRandomInt(all.length)]);
  }
  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}
function bindSecretVisibility(inputId, buttonId) {
  const input = document.getElementById(inputId);
  const button = document.getElementById(buttonId);
  if (!input || !button) return;
  button.addEventListener("click", (event) => {
    event.preventDefault();
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    button.querySelector(".eye-open")?.classList.toggle("hidden", visible);
    button.querySelector(".eye-closed")?.classList.toggle("hidden", !visible);
    button.setAttribute("aria-label", visible ? "Hide secret" : "Show secret");
  });
}
function initTOTPGenerator() {
  const secretInput = document.getElementById("genSecret");
  const randomBtn = document.getElementById("randomSecretBtn");
  const copyBtn = document.getElementById("copyGenSecret");
  const issuerInput = document.getElementById("genIssuer");
  const accountInput = document.getElementById("genAccount");
  const algoSelect = document.getElementById("genAlgo");
  const periodSelect = document.getElementById("genPeriod");
  const digitsSelect = document.getElementById("genDigits");
  bindSecretVisibility("genSecret", "toggleGenSecretVisibility");
  bindSecretVisibility("modalSecret", "toggleModalSecretVisibility");
  bindSecretVisibility("decSecret", "toggleDecSecretVisibility");
  document.getElementById("toggleGenPassVisibility")?.addEventListener("click", (e) => {
    e.preventDefault();
    const input = document.getElementById("genPassword");
    const eyeOpen = e.currentTarget.querySelector(".eye-open");
    const eyeClosed = e.currentTarget.querySelector(".eye-closed");
    if (input.type === "password") {
      input.type = "text";
      eyeOpen.classList.add("hidden");
      eyeClosed.classList.remove("hidden");
    } else {
      input.type = "password";
      eyeOpen.classList.remove("hidden");
      eyeClosed.classList.add("hidden");
    }
  });
  document.getElementById("genPassBtn")?.addEventListener("click", (e) => {
    e.preventDefault();
    const pass = generateRandomPassword(16);
    const input = document.getElementById("genPassword");
    if (input) {
      input.value = pass;
      input.type = "text";
      const btn = document.getElementById("toggleGenPassVisibility");
      btn?.querySelector(".eye-open")?.classList.add("hidden");
      btn?.querySelector(".eye-closed")?.classList.remove("hidden");
      showToast("Generated secure password!");
    }
  });
  document.getElementById("toggleModalPassVisibility")?.addEventListener("click", (e) => {
    e.preventDefault();
    const input = document.getElementById("modalPassword");
    const eyeOpen = e.currentTarget.querySelector(".eye-open");
    const eyeClosed = e.currentTarget.querySelector(".eye-closed");
    if (input.type === "password") {
      input.type = "text";
      eyeOpen.classList.add("hidden");
      eyeClosed.classList.remove("hidden");
    } else {
      input.type = "password";
      eyeOpen.classList.remove("hidden");
      eyeClosed.classList.add("hidden");
    }
  });
  document.getElementById("genModalPassBtn")?.addEventListener("click", (e) => {
    e.preventDefault();
    const pass = generateRandomPassword(16);
    const input = document.getElementById("modalPassword");
    if (input) {
      input.value = pass;
      input.type = "text";
      const btn = document.getElementById("toggleModalPassVisibility");
      btn?.querySelector(".eye-open")?.classList.add("hidden");
      btn?.querySelector(".eye-closed")?.classList.remove("hidden");
      showToast("Generated secure password!");
    }
  });
  document.getElementById("genModalSecretBtn")?.addEventListener("click", (e) => {
    e.preventDefault();
    const modalSecretInput = document.getElementById("modalSecret");
    if (modalSecretInput) {
      modalSecretInput.value = Base32.randomSecret();
      showToast(t("gen_random_btn"));
    }
  });
  renderQRCode();
  randomBtn?.addEventListener("click", () => {
    if (secretInput) {
      secretInput.value = Base32.randomSecret();
      renderQRCode();
      showToast(t("gen_random_btn"));
    }
  });
  copyBtn?.addEventListener("click", async () => {
    if (secretInput && secretInput.value) {
      const ok = await copyTextToClipboard(secretInput.value.trim());
      if (ok) showToast(t("toast_secret_copied"));
      else showToast(t("toast_copy_failed"), "error");
    }
  });
  [secretInput, issuerInput, accountInput, algoSelect, periodSelect, digitsSelect].forEach((el) => {
    el?.addEventListener("input", renderQRCode);
    el?.addEventListener("change", renderQRCode);
  });
  document.getElementById("copyOtpUrlBtn")?.addEventListener("click", async () => {
    const uri = getOtpAuthURI();
    if (uri) {
      const ok = await copyTextToClipboard(uri);
      if (ok) showToast(t("toast_otp_copied"));
      else showToast(t("toast_copy_failed"), "error");
    }
  });
  document.getElementById("downloadQRBtn")?.addEventListener("click", downloadQRPNG);
  document.getElementById("saveToVaultBtn")?.addEventListener("click", () => {
    const issuer = document.getElementById("genIssuer").value.trim();
    const account = document.getElementById("genAccount").value.trim();
    const secret = document.getElementById("genSecret").value.trim().toUpperCase().replace(/\s+/g, "");
    const password = document.getElementById("genPassword")?.value.trim() || "";
    if (!issuer || !account || !secret) {
      showToast(t("toast_required_fields"), "error");
      return;
    }
    if (!isValidBase32Secret(secret)) {
      showToast(t("toast_invalid_secret"), "error");
      return;
    }
    const newItem = {
      id: generateId("totp"),
      issuer,
      account,
      secret,
      password,
      digits: parseInt(document.getElementById("genDigits").value) || 6,
      period: parseInt(document.getElementById("genPeriod").value) || 30,
      algo: document.getElementById("genAlgo")?.value || "SHA1"
    };
    appState.totpAccounts.push(newItem);
    saveTOTPToStorage();
    renderTOTPCards();
    showToast(t("toast_totp_added"));
    document.querySelector('.totp-subpill[data-subtab="vault"]')?.click();
  });
  const modalBackdrop = document.getElementById("modalBackdrop");
  initAccessibleDialog(modalBackdrop);
  const closeModal = () => closeAccessibleDialog(modalBackdrop);
  const resetPasswordVisibility = (passId, toggleId) => {
    const input = document.getElementById(passId);
    if (input) input.type = "password";
    const btn = document.getElementById(toggleId);
    btn?.querySelector(".eye-open")?.classList.remove("hidden");
    btn?.querySelector(".eye-closed")?.classList.add("hidden");
  };
  document.getElementById("quickAdd2FABtn")?.addEventListener("click", (event) => {
    document.getElementById("modalIssuer").value = "";
    document.getElementById("modalAccount").value = "";
    document.getElementById("modalSecret").value = "";
    const modalPass = document.getElementById("modalPassword");
    if (modalPass) modalPass.value = "";
    resetPasswordVisibility("modalPassword", "toggleModalPassVisibility");
    resetPasswordVisibility("modalSecret", "toggleModalSecretVisibility");
    openAccessibleDialog(modalBackdrop, event.currentTarget, "modalIssuer");
  });
  document.getElementById("closeModalBtn")?.addEventListener("click", closeModal);
  document.getElementById("cancelModalBtn")?.addEventListener("click", closeModal);
  modalBackdrop.addEventListener("click", (e) => {
    if (e.target === modalBackdrop) closeModal();
  });
  document.getElementById("confirmAdd2FABtn")?.addEventListener("click", () => {
    const issuer = document.getElementById("modalIssuer").value.trim();
    const account = document.getElementById("modalAccount").value.trim();
    const secret = document.getElementById("modalSecret").value.trim().toUpperCase().replace(/\s+/g, "");
    const password = document.getElementById("modalPassword")?.value.trim() || "";
    if (!issuer || !account || !secret) {
      showToast(t("toast_required_fields"), "error");
      return;
    }
    if (!isValidBase32Secret(secret)) {
      showToast(t("toast_invalid_secret"), "error");
      return;
    }
    appState.totpAccounts.push({
      id: generateId("totp"),
      issuer,
      account,
      secret,
      password,
      digits: 6,
      period: 30,
      algo: "SHA1"
    });
    saveTOTPToStorage();
    renderTOTPCards();
    modalBackdrop.classList.add("hidden");
    showToast(t("toast_totp_added"));
  });
}
function getOtpAuthURI() {
  const secret = (document.getElementById("genSecret")?.value || "").trim().toUpperCase();
  if (!secret) return "";
  const issuer = encodeURIComponent(document.getElementById("genIssuer")?.value.trim() || "AeroPad");
  const account = encodeURIComponent(document.getElementById("genAccount")?.value.trim() || "user");
  const digits = document.getElementById("genDigits")?.value || "6";
  const period = document.getElementById("genPeriod")?.value || "30";
  const algo = document.getElementById("genAlgo")?.value || "SHA1";
  return buildOTPAuthURI({
    issuer: decodeURIComponent(issuer),
    account: decodeURIComponent(account),
    secret,
    digits: Number(digits),
    period: Number(period),
    algo
  });
}
function renderQRCode() {
  const uri = getOtpAuthURI();
  const container = document.getElementById("qrContainer");
  if (!container) return;
  const issVal = document.getElementById("genIssuer")?.value.trim();
  const accVal = document.getElementById("genAccount")?.value.trim();
  const prevIss = document.getElementById("previewIssuer");
  const prevAcc = document.getElementById("previewAccount");
  if (prevIss) prevIss.textContent = issVal || "---";
  if (prevAcc) prevAcc.textContent = accVal || "user@account";
  if (!uri) {
    container.innerHTML = `<span style="color:var(--text-muted);font-size:0.8rem;text-align:center;padding:10px;">${t("no_qr_placeholder")}</span>`;
    return;
  }
  try {
    if (typeof qrcode !== "undefined") {
      const qr = qrcode(0, "M");
      qr.addData(uri);
      qr.make();
      container.innerHTML = qr.createImgTag(5, 8);
    } else {
      container.innerHTML = `<span style="color:#F43F5E;font-size:0.8rem;text-align:center;padding:10px;">QR library not loaded (connection blocked?). The Secret Key below still works.</span>`;
    }
  } catch (err) {
    console.error("QR Render Error:", err);
    container.innerHTML = `<span style="color:#F43F5E;font-size:0.8rem;text-align:center;padding:10px;">QR render failed — check the Secret Key for invalid characters.</span>`;
  }
}
function downloadQRPNG() {
  const img = document.querySelector("#qrContainer img");
  if (!img) {
    showToast("No QR code to download yet.", "error");
    return;
  }
  const canvas = document.createElement("canvas");
  canvas.width = 300;
  canvas.height = 300;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, 300, 300);
  ctx.drawImage(img, 20, 20, 260, 260);
  const a = document.createElement("a");
  a.download = `2FA-${document.getElementById("genIssuer").value || "QR"}.png`;
  a.href = canvas.toDataURL("image/png");
  a.click();
  showToast(t("toast_qr_downloaded"));
}
async function renderTOTPCards() {
  const grid = document.getElementById("totpCardsGrid");
  if (!grid) return;
  grid.innerHTML = "";
  if (appState.totpAccounts.length === 0) {
    grid.innerHTML = `
      <div class="empty-state-totp glass-panel">
        <div class="empty-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
        </div>
        <h3>${t("empty_totp_title")}</h3>
        <p>${t("empty_totp_desc")}</p>
      </div>
    `;
    return;
  }
  for (const acc of appState.totpAccounts) {
    const card = document.createElement("div");
    card.className = "totp-card glass-panel";
    card.dataset.accId = acc.id;
    card.setAttribute("tabindex", "0");
    card.setAttribute("role", "button");
    card.setAttribute("aria-label", `Copy current 2FA code for ${acc.issuer} (${acc.account})`);
    const initial = (acc.issuer || "2F").charAt(0).toUpperCase();
    const displayAlgorithm = normalizeAlgorithm2(acc.algo);
    const algorithmLabel = displayAlgorithm ? `HMAC-${displayAlgorithm}` : "Algorithm unavailable";
    const digitsLabel = acc.digits === 6 || acc.digits === 8 ? `${acc.digits} digits` : "Digits unavailable";
    const periodLabel = Number.isInteger(acc.period) && acc.period > 0 ? `${acc.period}s` : "Period unavailable";
    const renderTimestamp = Math.floor(Date.now() / 1e3);
    lastTOTPWindows.set(acc.id, getTOTPWindowIndex(renderTimestamp, acc.period));
    const currentCode = await generateTOTP(acc.secret, {
      period: acc.period,
      digits: acc.digits,
      algo: normalizeAlgorithm2(acc.algo),
      timestamp: renderTimestamp
    });
    const formattedCode = formatOTPCode(currentCode);
    const hasPassword = Boolean(acc.password && acc.password.trim().length > 0);
    const passwordRowHTML = hasPassword ? `
      <div class="totp-card-password-row">
        <div class="pass-label-col">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="pass-icon"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
          <span class="pass-masked-val" id="pass-val-${acc.id}">••••••••••••</span>
        </div>
        <div class="pass-actions-col">
          <button class="btn-icon-xs toggle-card-pass" data-id="${acc.id}" title="Show/Hide Password">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="eye-open"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="eye-closed hidden"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
          </button>
          <button class="btn-icon-xs copy-card-pass" data-id="${acc.id}" title="Copy Password">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
          </button>
        </div>
      </div>
    ` : "";
    card.innerHTML = `
      <div class="totp-card-top">
        <div class="totp-issuer-group">
          <div class="totp-avatar">${initial}</div>
          <div>
            <div class="totp-issuer-title">${escapeHTML(acc.issuer)}</div>
            <div class="totp-account-label">${escapeHTML(acc.account)}</div>
          </div>
        </div>
        <button class="btn-danger-ghost delete-totp-btn" title="Delete account">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
        </button>
      </div>

      <div class="totp-code-box">
        <div class="totp-code-text" id="code-${acc.id}">${formattedCode}</div>
        <button class="btn-copy-code" title="Copy 6-digit code">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
        </button>
      </div>

      ${passwordRowHTML}

      <div class="totp-card-footer">
        <span>RFC 6238 ${algorithmLabel} • ${digitsLabel}</span>
        <span class="font-mono text-cyan">${periodLabel}</span>
      </div>
      <div class="totp-card-progress">
        <div class="totp-card-progress-bar" id="prog-${acc.id}"></div>
      </div>
    `;
    card.querySelector(".btn-copy-code")?.addEventListener("click", (e) => {
      e.stopPropagation();
      copyVaultCode(acc);
    });
    if (hasPassword) {
      card.querySelector(".copy-card-pass")?.addEventListener("click", async (e) => {
        e.stopPropagation();
        const ok = await copyTextToClipboard(acc.password);
        if (ok) showToast(t("toast_pass_copied"));
        else showToast(t("toast_copy_failed"), "error");
      });
      card.querySelector(".toggle-card-pass")?.addEventListener("click", (e) => {
        e.stopPropagation();
        const btn = e.currentTarget;
        const valEl = document.getElementById(`pass-val-${acc.id}`);
        const eyeOpen = btn.querySelector(".eye-open");
        const eyeClosed = btn.querySelector(".eye-closed");
        if (valEl.textContent === "••••••••••••") {
          valEl.textContent = acc.password;
          eyeOpen.classList.add("hidden");
          eyeClosed.classList.remove("hidden");
        } else {
          valEl.textContent = "••••••••••••";
          eyeOpen.classList.remove("hidden");
          eyeClosed.classList.add("hidden");
        }
      });
    }
    const interactiveTarget = (e) => e.target.closest(".delete-totp-btn") || e.target.closest(".totp-card-password-row") || e.target.closest(".btn-copy-code");
    card.addEventListener("click", (e) => {
      if (interactiveTarget(e)) return;
      copyVaultCode(acc);
    });
    card.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      if (interactiveTarget(e)) return;
      e.preventDefault();
      copyVaultCode(acc);
    });
    card.querySelector(".delete-totp-btn")?.addEventListener("click", (e) => {
      e.stopPropagation();
      if (!window.confirm(t("confirm_delete_totp"))) return;
      appState.totpAccounts = appState.totpAccounts.filter((a) => a.id !== acc.id);
      saveTOTPToStorage();
      renderTOTPCards();
      showToast(t("toast_deleted_totp"));
    });
    grid.appendChild(card);
  }
}
var lastTOTPWindows = /* @__PURE__ */ new Map();
var lastDecodedTOTPWindow = null;
function getTOTPWindowIndex(nowSeconds, period = 30) {
  const safePeriod = Number.isInteger(period) && period > 0 ? period : 30;
  return Math.floor(nowSeconds / safePeriod);
}
function getTOTPCountdown(nowSeconds, period = 30) {
  const safePeriod = Number.isInteger(period) && period > 0 ? period : 30;
  const remainingSeconds = safePeriod - nowSeconds % safePeriod;
  return { remainingSeconds, percent: remainingSeconds / safePeriod * 100 };
}
function startGlobalTOTPTimer() {
  setInterval(async () => {
    const now = Math.floor(Date.now() / 1e3);
    const secEl = document.getElementById("globalCountdownSec");
    const circleEl = document.getElementById("globalCountdownCircle");
    if (secEl) secEl.textContent = appState.totpAccounts.length ? "LIVE" : "--";
    if (circleEl) {
      circleEl.setAttribute("stroke-dasharray", "100, 100");
      circleEl.classList.remove("expiring");
    }
    const decProg = document.getElementById("decProgressFill");
    if (decProg && currentDecodedItem) {
      const dPeriod = currentDecodedItem.period || 30;
      const { percent } = getTOTPCountdown(now, dPeriod);
      decProg.style.width = `${percent}%`;
    }
    const changedAccounts = [];
    appState.totpAccounts.forEach((acc) => {
      const currentWindow = getTOTPWindowIndex(now, acc.period);
      const previousWindow = lastTOTPWindows.get(acc.id);
      lastTOTPWindows.set(acc.id, currentWindow);
      if (previousWindow !== void 0 && previousWindow !== currentWindow) {
        changedAccounts.push(acc);
      }
    });
    let decoderChanged = false;
    if (currentDecodedSecret && currentDecodedItem) {
      const currentWindow = getTOTPWindowIndex(now, currentDecodedItem.period);
      decoderChanged = lastDecodedTOTPWindow !== null && lastDecodedTOTPWindow !== currentWindow;
      lastDecodedTOTPWindow = currentWindow;
    } else {
      lastDecodedTOTPWindow = null;
    }
    if (changedAccounts.length > 0 || decoderChanged) {
      updateAllTOTPValues(changedAccounts, decoderChanged, now);
    }
    appState.totpAccounts.forEach((acc) => {
      const p = document.getElementById(`prog-${acc.id}`);
      if (!p) return;
      const { percent } = getTOTPCountdown(now, acc.period);
      p.style.width = `${percent}%`;
    });
  }, 1e3);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      lastTOTPWindows.clear();
      lastDecodedTOTPWindow = null;
      updateAllTOTPValues(appState.totpAccounts, true);
    }
  });
}
async function updateAllTOTPValues(accounts = appState.totpAccounts, updateDecoder = true, timestampSeconds = Math.floor(Date.now() / 1e3)) {
  for (const acc of accounts) {
    const code = await generateTOTP(acc.secret, {
      period: acc.period,
      digits: acc.digits,
      algo: normalizeAlgorithm2(acc.algo),
      timestamp: timestampSeconds
    });
    const el = document.getElementById(`code-${acc.id}`);
    if (el) {
      el.textContent = formatOTPCode(code);
      el.setAttribute("aria-label", code ? `Current code ${code}` : "Code unavailable");
    }
    lastTOTPWindows.set(acc.id, getTOTPWindowIndex(timestampSeconds, acc.period));
  }
  if (updateDecoder && currentDecodedSecret && currentDecodedItem) {
    const testCode = await generateTOTP(currentDecodedSecret, {
      period: currentDecodedItem.period,
      digits: currentDecodedItem.digits,
      algo: normalizeAlgorithm2(currentDecodedItem.algo),
      timestamp: timestampSeconds
    });
    const display = document.getElementById("decLiveCode");
    if (display) {
      if (testCode) {
        const parts = formatOTPCode(testCode).split(" ");
        display.innerHTML = `<span>${parts[0]}</span> <span>${parts[1] || ""}</span>`;
      } else {
        display.textContent = "------";
      }
    }
    lastDecodedTOTPWindow = getTOTPWindowIndex(timestampSeconds, currentDecodedItem.period);
  }
}
var currentDecodedSecret = null;
var currentDecodedItem = null;
function initDecoder() {
  const dropZone = document.getElementById("qrDropZone");
  const fileInput = document.getElementById("qrFileInput");
  const decodeBtn = document.getElementById("decodeBtn");
  const rawInput = document.getElementById("rawOtpInput");
  if (!dropZone) return;
  dropZone.addEventListener("click", () => fileInput.click());
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      handleQRFile(e.dataTransfer.files[0]);
    }
  });
  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      handleQRFile(e.target.files[0]);
    }
  });
  window.addEventListener("paste", (e) => {
    if (appState.currentTab === "totp" && appState.current2FASubtab === "decoder") {
      if (e.target && (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA")) return;
      const items = (e.clipboardData || e.originalEvent.clipboardData).items;
      for (const item of items) {
        if (item.type.indexOf("image") !== -1) {
          const blob = item.getAsFile();
          handleQRFile(blob);
          return;
        }
      }
      const text = (e.clipboardData || e.originalEvent.clipboardData).getData("text") || "";
      if (text.trim()) {
        handleOTPAuthInput(text.trim());
      }
    }
  });
  decodeBtn?.addEventListener("click", () => {
    const text = rawInput.value.trim();
    if (!text) {
      showToast(t("paste_prompt"), "error");
      return;
    }
    handleOTPAuthInput(text);
  });
  let decoderEditTimer = null;
  ["decIssuer", "decAccount", "decSecret"].forEach((id) => {
    document.getElementById(id)?.addEventListener("input", () => {
      clearTimeout(decoderEditTimer);
      decoderEditTimer = setTimeout(syncDecoderItemFromFields, 250);
    });
  });
  document.getElementById("copyDecSecret")?.addEventListener("click", async () => {
    if (currentDecodedSecret) {
      const ok = await copyTextToClipboard(currentDecodedSecret);
      if (ok) showToast(t("toast_secret_copied"));
      else showToast(t("toast_copy_failed"), "error");
    }
  });
  document.getElementById("toggleDecPassVisibility")?.addEventListener("click", (e) => {
    e.preventDefault();
    const input = document.getElementById("decPasswordInput");
    const eyeOpen = e.currentTarget.querySelector(".eye-open");
    const eyeClosed = e.currentTarget.querySelector(".eye-closed");
    if (input.type === "password") {
      input.type = "text";
      eyeOpen.classList.add("hidden");
      eyeClosed.classList.remove("hidden");
    } else {
      input.type = "password";
      eyeOpen.classList.remove("hidden");
      eyeClosed.classList.add("hidden");
    }
  });
  document.getElementById("addDecodedToVaultBtn")?.addEventListener("click", () => {
    syncDecoderItemFromFields();
    if (!currentDecodedItem) {
      showToast(t("toast_invalid_secret"), "error");
      return;
    }
    const password = document.getElementById("decPasswordInput")?.value.trim() || "";
    appState.totpAccounts.push({
      id: generateId("totp"),
      issuer: currentDecodedItem.issuer,
      account: currentDecodedItem.account,
      secret: currentDecodedItem.secret,
      password,
      digits: currentDecodedItem.digits,
      period: currentDecodedItem.period,
      algo: currentDecodedItem.algo
    });
    saveTOTPToStorage();
    renderTOTPCards();
    showToast(t("toast_totp_added"));
    document.querySelector('.totp-subpill[data-subtab="vault"]')?.click();
  });
}
var MAX_QR_CANVAS_EDGE = 2048;
function getBoundedQRCanvasSize(width, height) {
  const longestEdge = Math.max(width, height);
  const scale = longestEdge > MAX_QR_CANVAS_EDGE ? MAX_QR_CANVAS_EDGE / longestEdge : 1;
  return {
    width: Math.max(1, Math.round(width * scale)),
    height: Math.max(1, Math.round(height * scale))
  };
}
function handleQRFile(file) {
  if (!file) return;
  if (!file.type || !file.type.startsWith("image/")) {
    showToast(t("toast_not_an_image"), "error");
    return;
  }
  const reader = new FileReader();
  reader.onerror = () => showToast(t("toast_qr_read_failed"), "error");
  reader.onload = (e) => {
    const img = new Image();
    img.onerror = () => showToast(t("toast_not_an_image"), "error");
    img.onload = () => {
      if (img.width > 4096 || img.height > 4096) {
        showToast(t("toast_image_too_large"), "error");
        return;
      }
      const canvasSize = getBoundedQRCanvasSize(img.width, img.height);
      const canvas = document.createElement("canvas");
      canvas.width = canvasSize.width;
      canvas.height = canvasSize.height;
      const ctx = canvas.getContext("2d");
      if (!ctx) {
        showToast(t("toast_qr_read_failed"), "error");
        return;
      }
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      if (typeof jsQR !== "undefined") {
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code) {
          showToast(t("toast_qr_detected"));
          handleOTPAuthInput(code.data);
        } else {
          showToast("Failed to decode QR code from image.", "error");
        }
      } else {
        showToast("jsQR library not loaded", "error");
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}
function syncDecoderItemFromFields() {
  const issEl = document.getElementById("decIssuer");
  const accEl = document.getElementById("decAccount");
  const secEl = document.getElementById("decSecret");
  const secret = (secEl && secEl.value || "").replace(/[\s-]/g, "").toUpperCase();
  const prev = currentDecodedItem;
  const parsed = parseOTPAuthURI(secret);
  if (!parsed.isValid) {
    currentDecodedSecret = null;
    currentDecodedItem = null;
    lastDecodedTOTPWindow = null;
    const live = document.getElementById("decLiveCode");
    if (live) live.textContent = "------";
    return;
  }
  currentDecodedSecret = secret;
  currentDecodedItem = {
    issuer: issEl && issEl.value.trim() || parsed.issuer,
    account: accEl && accEl.value.trim() || parsed.account,
    secret,
    digits: prev ? prev.digits : parsed.digits,
    period: prev ? prev.period : parsed.period,
    algo: prev ? prev.algo : parsed.algo
  };
  refreshDecoderLiveCode();
}
async function refreshDecoderLiveCode() {
  if (!currentDecodedItem) return;
  const { secret, digits, period, algo } = currentDecodedItem;
  lastDecodedTOTPWindow = getTOTPWindowIndex(Math.floor(Date.now() / 1e3), period);
  const code = await generateTOTP(secret, {
    period,
    digits,
    algo: normalizeAlgorithm2(algo)
  });
  const display = document.getElementById("decLiveCode");
  if (!display) return;
  if (code) {
    const parts = formatOTPCode(code).split(" ");
    display.innerHTML = `<span>${parts[0]}</span> <span>${parts[1] || ""}</span>`;
  } else {
    display.textContent = "------";
  }
}
async function handleOTPAuthInput(input) {
  const parsed = parseOTPAuthURI(input);
  if (!parsed.isValid) {
    showToast(t("toast_invalid_secret"), "error");
    return;
  }
  const { issuer, account, secret, digits, period, algo } = parsed;
  currentDecodedSecret = secret;
  currentDecodedItem = parsed;
  lastDecodedTOTPWindow = getTOTPWindowIndex(Math.floor(Date.now() / 1e3), period);
  const decIss = document.getElementById("decIssuer");
  const decAcc = document.getElementById("decAccount");
  const decSec = document.getElementById("decSecret");
  if (decIss) decIss.value = issuer;
  if (decAcc) decAcc.value = account;
  if (decSec) decSec.value = secret;
  const liveCode = await generateTOTP(secret, {
    period,
    digits,
    algo: normalizeAlgorithm2(algo)
  });
  const liveDisplay = document.getElementById("decLiveCode");
  if (liveDisplay) {
    if (liveCode) {
      const parts = formatOTPCode(liveCode).split(" ");
      liveDisplay.innerHTML = `<span>${parts[0]}</span> <span>${parts[1] || ""}</span>`;
    } else {
      liveDisplay.textContent = "------";
    }
  }
  document.getElementById("decoderResultCard")?.scrollIntoView({ behavior: "smooth" });
}
function escapeHTML(str) {
  return (str || "").replace(/[&<>'"]/g, (tag) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;"
  })[tag] || tag);
}
function formatTimeAgo(timestamp) {
  const diff = Date.now() - timestamp;
  const mins = Math.floor(diff / 6e4);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
