import { Base32 } from './base32.js';

const MIN_PERIOD = 1;
const MAX_PERIOD = 3600;
const SUPPORTED_DIGITS = new Set([6, 8]);

/**
 * Normalize OTPAuth/Web Crypto algorithm spellings without silently falling
 * back to SHA-1 for an unsupported algorithm.
 */
export function normalizeAlgorithm(algo = 'SHA-1') {
  const clean = String(algo).toUpperCase().replace(/-/g, '');
  if (clean === 'SHA1') return 'SHA-1';
  if (clean === 'SHA256') return 'SHA-256';
  if (clean === 'SHA512') return 'SHA-512';
  return null;
}

function isValidPeriod(period) {
  return Number.isInteger(period) && period >= MIN_PERIOD && period <= MAX_PERIOD;
}

function isValidTimestamp(timestamp) {
  return Number.isInteger(timestamp) && timestamp >= 0;
}

/**
 * RFC 6238 Time-Based One-Time Password (TOTP) Generator
 */
export async function generateTOTP(secretBase32, options = {}) {
  const {
    period = 30,
    digits = 6,
    algo = 'SHA-1',
    timestamp = Math.floor(Date.now() / 1000)
  } = options;

  try {
    const normalizedAlgo = normalizeAlgorithm(algo);
    if (!secretBase32 || typeof secretBase32 !== 'string' ||
        !isValidPeriod(period) || !SUPPORTED_DIGITS.has(digits) ||
        !normalizedAlgo || !isValidTimestamp(timestamp)) {
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
      const nodeCrypto = await import('node:crypto');
      subtleCrypto = nodeCrypto.webcrypto.subtle;
    }

    const cryptoKey = await subtleCrypto.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: { name: normalizedAlgo } },
      false,
      ['sign']
    );

    const signature = await subtleCrypto.sign('HMAC', cryptoKey, counterBuffer);
    const hmacBytes = new Uint8Array(signature);

    const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
    const binary =
      ((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff);

    const otp = binary % Math.pow(10, digits);
    return otp.toString().padStart(digits, '0');
  } catch (err) {
    console.error('TOTP Generation Error:', err);
    return null;
  }
}

/**
 * Calculates countdown seconds and progress percentage
 */
export function calculateRemainingTime(epochSeconds = Math.floor(Date.now() / 1000), period = 30) {
  if (!isValidPeriod(period) || !isValidTimestamp(epochSeconds)) {
    throw new RangeError('period and epochSeconds must be non-negative integers within the supported range');
  }
  const remain = period - (epochSeconds % period);
  const percent = (remain / period) * 100;
  return {
    remainingSeconds: remain,
    percent: Math.round(percent * 100) / 100
  };
}
