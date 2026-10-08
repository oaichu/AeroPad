// src/lib/aeropad-format.ts
import type { Vault } from '../types/index.js';
import { isVault } from '../types/index.js';
import { deriveKey, encrypt, decrypt, randomBytes, bytesToBase64Url, base64UrlToBytes } from './crypto.js';
import { KDF_ITERATIONS } from './crypto.js';

interface AeropadFile {
  v: 1;
  kdf: { algo: 'PBKDF2-SHA256'; iter: number; salt: string };
  iv: string;
  ciphertext: string;
  meta: { createdAt: number; modifiedAt: number; entryCount: number };
}

// Accept files produced by this extension and the AeroPad web app
// (600k–2M iters). Bound the value anyway: an attacker-controlled file
// could otherwise freeze the service worker with e.g. iter = 2**31.
const KDF_ITER_MIN = 1;
const KDF_ITER_MAX = 5_000_000;
const CIPHERTEXT_MAX = 16 * 1024 * 1024; // base64 chars, ~12 MB plaintext

export async function exportVault(
  vault: Vault,
  password: string,
): Promise<string> {
  const salt = randomBytes(16);
  const key = await deriveKey(password, salt, KDF_ITERATIONS);
  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  const { iv, ciphertext } = await encrypt(plaintext, key);
  const file: AeropadFile = {
    v: 1,
    kdf: { algo: 'PBKDF2-SHA256', iter: KDF_ITERATIONS, salt: bytesToBase64Url(salt) },
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(ciphertext),
    meta: {
      createdAt: Date.now(),
      modifiedAt: Date.now(),
      entryCount: vault.codes.length,
    },
  };
  return JSON.stringify(file, null, 2);
}

export async function importVault(json: string, password: string): Promise<Vault> {
  let file: unknown;
  try { file = JSON.parse(json); } catch { throw new Error('Malformed .aeropad file'); }
  if (typeof file !== 'object' || file === null) throw new Error('Malformed .aeropad file');
  const f = file as Partial<AeropadFile>;
  if (f.v !== 1 || !f.kdf || !f.iv || !f.ciphertext) throw new Error('Unsupported .aeropad version');
  if (f.kdf.algo !== 'PBKDF2-SHA256') throw new Error('Unsupported KDF algorithm');
  if (!Number.isSafeInteger(f.kdf.iter) || f.kdf.iter < KDF_ITER_MIN || f.kdf.iter > KDF_ITER_MAX) {
    throw new Error('Unsupported KDF iterations');
  }
  if (typeof f.ciphertext !== 'string' || f.ciphertext.length > CIPHERTEXT_MAX) {
    throw new Error('Malformed .aeropad file');
  }

  const key = await deriveKey(password, base64UrlToBytes(f.kdf.salt), f.kdf.iter);
  let plaintext: Uint8Array;
  try {
    plaintext = await decrypt(base64UrlToBytes(f.ciphertext), base64UrlToBytes(f.iv), key);
  } catch {
    throw new Error('Wrong password or corrupted file');
  }
  const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
  if (!isVault(parsed)) throw new Error('Invalid vault structure');
  return parsed;
}