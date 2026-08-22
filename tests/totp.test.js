import test from 'node:test';
import assert from 'node:assert/strict';
import { generateTOTP, calculateRemainingTime } from '../src/crypto/totp.js';

test('TOTP - Verifies RFC 6238 official SHA-1 test vectors', async () => {
  // Secret: "12345678901234567890" in Base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  // Test vector 1: Time = 59s
  const otp1 = await generateTOTP(secret, { timestamp: 59, period: 30, digits: 8, algo: 'SHA-1' });
  assert.equal(otp1, '94287082');

  const otp1_6 = await generateTOTP(secret, { timestamp: 59, period: 30, digits: 6, algo: 'SHA-1' });
  assert.equal(otp1_6, '287082');

  // Test vector 2: Time = 1111111109s
  const otp2 = await generateTOTP(secret, { timestamp: 1111111109, period: 30, digits: 8, algo: 'SHA-1' });
  assert.equal(otp2, '07081804');

  // Test vector 3: Time = 1234567890s
  const otp3 = await generateTOTP(secret, { timestamp: 1234567890, period: 30, digits: 8, algo: 'SHA-1' });
  assert.equal(otp3, '89005924');

  // Test vector 4: Time = 2000000000s
  const otp4 = await generateTOTP(secret, { timestamp: 2000000000, period: 30, digits: 8, algo: 'SHA-1' });
  assert.equal(otp4, '69279037');
});

test('TOTP - Calculates remaining epoch countdown correctly', () => {
  // At epoch 45s with period 30s: 30 - (45 % 30) = 15s remaining
  const res1 = calculateRemainingTime(45, 30);
  assert.equal(res1.remainingSeconds, 15);
  assert.equal(res1.percent, 50);

  // At epoch 60s with period 30s: 30 - (60 % 30) = 30s remaining
  const res2 = calculateRemainingTime(60, 30);
  assert.equal(res2.remainingSeconds, 30);
  assert.equal(res2.percent, 100);
});

test('TOTP - Returns null on malformed secret instead of a fake "000000" code', async () => {
  // A fake all-zeros code looks valid to users and gets typed into real services.
  const empty = await generateTOTP('', { digits: 6 });
  assert.equal(empty, null);

  const garbage = await generateTOTP('0000000000000000', { digits: 6 });
  assert.equal(garbage, null);
});

test('TOTP - RFC 6238 vectors pass for SHA-256 accounts too', async () => {
  // Secret "12345678901234567890123456789012" Base32, official SHA-256 vector at t=59
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA';
  const otp = await generateTOTP(secret, { timestamp: 59, period: 30, digits: 8, algo: 'SHA-256' });
  assert.equal(otp, '46119246');
});

test('TOTP - Supports SHA-512 and non-default account periods', async () => {
  const secret = 'JBSWY3DPEHPK3PXP';

  for (const period of [15, 45, 60]) {
    const code = await generateTOTP(secret, {
      timestamp: 1234567890,
      period,
      digits: 8,
      algo: 'SHA-512'
    });
    assert.match(code, /^\d{8}$/, `period=${period}`);
  }
});

test('TOTP - Rejects unsupported algorithms, digits and periods', async () => {
  const secret = 'JBSWY3DPEHPK3PXP';

  assert.equal(await generateTOTP(secret, { algo: 'MD5' }), null);
  assert.equal(await generateTOTP(secret, { digits: 7 }), null);
  assert.equal(await generateTOTP(secret, { period: 0 }), null);
  assert.equal(await generateTOTP(secret, { period: 3601 }), null);
  assert.throws(() => calculateRemainingTime(0, 0), /period/i);
});

test('TOTP - calculateRemainingTime never reports 0 remaining seconds', () => {
  // At the exact boundary a NEW window starts, so remaining is a full period
  for (let ts = 0; ts < 130; ts++) {
    const { remainingSeconds } = calculateRemainingTime(ts, 30);
    assert.ok(remainingSeconds >= 1 && remainingSeconds <= 30, `t=${ts} -> ${remainingSeconds}`);
  }
});
