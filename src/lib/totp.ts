// src/lib/totp.ts
import type { CodeEntry, TotpAlgorithm } from '../types/index.js';
import { base32Decode } from './base32.js';

const ALGO_MAP: Record<TotpAlgorithm, string> = {
  SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512',
};

function counter(t: number, period: number): Uint8Array {
  const c = Math.floor(t / period);
  const b = new ArrayBuffer(8);
  const view = new DataView(b);
  view.setUint32(0, Math.floor(c / 0x100000000));
  view.setUint32(4, c >>> 0);
  return new Uint8Array(b);
}

function hotp(secret: Uint8Array, counter: Uint8Array, algorithm: string, digits: number): string {
  return crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: algorithm }, false, ['sign'])
    .then((key) => crypto.subtle.sign('HMAC', key, counter))
    .then((sig) => {
      const bytes = new Uint8Array(sig);
      const offset = bytes[bytes.length - 1]! & 0x0f;
      const bin = ((bytes[offset]! & 0x7f) << 24)
        | ((bytes[offset + 1]! & 0xff) << 16)
        | ((bytes[offset + 2]! & 0xff) << 8)
        | (bytes[offset + 3]! & 0xff);
      const mod = bin % 10 ** digits;
      return mod.toString().padStart(digits, '0');
    });
}

export async function totp(
  secret: string,
  opts: { algorithm: TotpAlgorithm; digits: 6 | 8; period: number; t: number },
): Promise<string> {
  const key = base32Decode(secret);
  return hotp(key, counter(opts.t, opts.period), ALGO_MAP[opts.algorithm], opts.digits);
}

export async function currentCode(entry: CodeEntry, now: number = Date.now()): Promise<string> {
  return totp(entry.secret, {
    algorithm: entry.algorithm, digits: entry.digits, period: entry.period, t: Math.floor(now / 1000),
  });
}

export function remainingSeconds(entry: CodeEntry, now: number = Date.now()): number {
  const t = Math.floor(now / 1000);
  return entry.period - (t % entry.period);
}