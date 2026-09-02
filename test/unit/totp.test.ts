import { describe, it, expect } from 'vitest';
import { totp, currentCode, remainingSeconds } from '../../src/lib/totp.js';

describe('totp RFC 6238 vectors', () => {
  // SHA-1, 8-digit, secret = "12345678901234567890"
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // base32 of "12345678901234567890"

  it('T=59 → 94287082', async () => {
    expect(await totp(secret, { algorithm: 'SHA1', digits: 8, period: 30, t: 59 })).toBe('94287082');
  });
  it('T=1111111109 → 07081804', async () => {
    expect(await totp(secret, { algorithm: 'SHA1', digits: 8, period: 30, t: 1111111109 })).toBe('07081804');
  });
  it('T=1111111111 → 14050471', async () => {
    expect(await totp(secret, { algorithm: 'SHA1', digits: 8, period: 30, t: 1111111111 })).toBe('14050471');
  });
  it('T=1234567890 → 89005924', async () => {
    expect(await totp(secret, { algorithm: 'SHA1', digits: 8, period: 30, t: 1234567890 })).toBe('89005924');
  });
  it('T=2000000000 → 69279037', async () => {
    expect(await totp(secret, { algorithm: 'SHA1', digits: 8, period: 30, t: 2000000000 })).toBe('69279037');
  });
});

describe('currentCode & remainingSeconds', () => {
  const entry = {
    id: '1', issuer: 'X', account: 'a', secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA1' as const, digits: 6 as const, period: 30, createdAt: 0,
  };

  it('currentCode returns 6 digits', async () => {
    expect(await currentCode(entry)).toMatch(/^\d{6}$/);
  });

  it('remainingSeconds is in (0, 30]', () => {
    const r = remainingSeconds(entry);
    expect(r).toBeGreaterThan(0);
    expect(r).toBeLessThanOrEqual(30);
  });
});