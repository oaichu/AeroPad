import { describe, it, expect } from 'vitest';
import { totp, currentCode, remainingSeconds, parseOtpauthUri } from '../../src/lib/totp.js';

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
  it('supports secret with dashes and spaces', async () => {
    const dashed = 'GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ';
    expect(await totp(dashed, { algorithm: 'SHA-1' as any, digits: 8, period: 30, t: 59 })).toBe('94287082');
  });
});

describe('parseOtpauthUri', () => {
  it('parses standard URI with issuer param and colon label', () => {
    const res = parseOtpauthUri('otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub');
    expect(res).not.toBeNull();
    expect(res?.issuer).toBe('GitHub');
    expect(res?.account).toBe('user');
    expect(res?.secret).toBe('JBSWY3DPEHPK3PXP');
    expect(res?.algorithm).toBe('SHA1');
    expect(res?.digits).toBe(6);
    expect(res?.period).toBe(30);
  });

  it('parses URI without explicit issuer param by using label', () => {
    const res = parseOtpauthUri('otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP');
    expect(res).not.toBeNull();
    expect(res?.issuer).toBe('alice@example.com');
    expect(res?.account).toBe('alice@example.com');
  });

  it('parses URI with hyphenated algorithm SHA-256 and SHA-512 correctly', () => {
    const res256 = parseOtpauthUri('otpauth://totp/Service:u?secret=JBSWY3DPEHPK3PXP&algorithm=SHA-256&digits=8&period=60');
    expect(res256?.algorithm).toBe('SHA256');
    expect(res256?.digits).toBe(8);
    expect(res256?.period).toBe(60);

    const res512 = parseOtpauthUri('otpauth://totp/Service:u?secret=JBSWY3DPEHPK3PXP&algorithm=sha-512');
    expect(res512?.algorithm).toBe('SHA512');
  });

  it('cleans dashes and spaces in URI secret', () => {
    const res = parseOtpauthUri('otpauth://totp/S:u?secret=JBSW-Y3DP-EHPK-3PXP');
    expect(res?.secret).toBe('JBSWY3DPEHPK3PXP');
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

  it('currentCode works with normalized algorithm strings like SHA-1', async () => {
    const entryHyphen = { ...entry, algorithm: 'SHA-1' as any };
    expect(await currentCode(entryHyphen)).toMatch(/^\d{6}$/);
  });

  it('remainingSeconds is in (0, 30]', () => {
    const r = remainingSeconds(entry);
    expect(r).toBeGreaterThan(0);
    expect(r).toBeLessThanOrEqual(30);
  });
});