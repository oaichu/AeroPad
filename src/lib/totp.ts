// src/lib/totp.ts
import type { CodeEntry, TotpAlgorithm } from '../types/index.js';
import { base32Decode } from './base32.js';

export function normalizeTotpAlgorithm(algo: string = 'SHA1'): { type: TotpAlgorithm; webCrypto: string } {
  const clean = String(algo || '').toUpperCase().replace(/-/g, '');
  if (clean === 'SHA256') return { type: 'SHA256', webCrypto: 'SHA-256' };
  if (clean === 'SHA512') return { type: 'SHA512', webCrypto: 'SHA-512' };
  return { type: 'SHA1', webCrypto: 'SHA-1' };
}

function counter(t: number, period: number): Uint8Array {
  const c = Math.floor(t / period);
  const b = new ArrayBuffer(8);
  const view = new DataView(b);
  view.setUint32(0, Math.floor(c / 0x100000000));
  view.setUint32(4, c >>> 0);
  return new Uint8Array(b);
}

function hotp(secret: Uint8Array, counter: Uint8Array, algorithm: string, digits: number): Promise<string> {
  return crypto.subtle.importKey('raw', secret as BufferSource, { name: 'HMAC', hash: algorithm }, false, ['sign'])
    .then((key) => crypto.subtle.sign('HMAC', key, counter as BufferSource))
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
  opts: { algorithm: TotpAlgorithm | string; digits: 6 | 8; period: number; t: number },
): Promise<string> {
  const key = base32Decode(secret);
  const norm = normalizeTotpAlgorithm(opts.algorithm);
  return hotp(key, counter(opts.t, opts.period), norm.webCrypto, opts.digits);
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

export interface ParsedOtpauth {
  issuer: string;
  account: string;
  secret: string;
  algorithm: TotpAlgorithm;
  digits: 6 | 8;
  period: number;
}

export function parseOtpauthUri(uri: string): ParsedOtpauth | null {
  try {
    const trimmed = uri.trim();
    if (!trimmed.toLowerCase().startsWith('otpauth://totp/')) return null;
    const url = new URL(trimmed);
    const secret = (url.searchParams.get('secret') || '').replace(/[\s-]+/g, '').toUpperCase();
    if (!secret || !/^[A-Z2-7]+=*$/.test(secret)) return null;

    let issuer = (url.searchParams.get('issuer') || '').trim();
    let account = '';
    const rawLabel = decodeURIComponent(url.pathname.replace(/^\/\/totp\//, '').replace(/^\/totp\//, '').replace(/^\//, ''));
    if (rawLabel.includes(':')) {
      const parts = rawLabel.split(':');
      if (!issuer && parts[0]) issuer = parts[0].trim();
      account = parts.slice(1).join(':').trim();
    } else {
      account = rawLabel.trim();
    }
    if (!issuer && account) {
      issuer = account;
    }
    if (!issuer) {
      issuer = 'Custom 2FA';
    }

    const algoParam = url.searchParams.get('algorithm') || 'SHA1';
    const algorithm = normalizeTotpAlgorithm(algoParam).type;

    const digitsParam = Number(url.searchParams.get('digits'));
    const digits: 6 | 8 = digitsParam === 8 ? 8 : 6;

    const periodParam = Number(url.searchParams.get('period'));
    const period = periodParam > 0 ? periodParam : 30;

    return { issuer, account, secret, algorithm, digits, period };
  } catch {
    return null;
  }
}