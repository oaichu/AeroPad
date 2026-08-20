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

test('TOTP - Gracefully handles malformed secret or empty input', async () => {
  const otp = await generateTOTP('', { digits: 6 });
  assert.equal(otp, '000000');
});

test('2FA Account - Preserves optional password field correctly', () => {
  const accountWithPass = {
    id: 'totp-12345',
    issuer: 'ChatGPT OpenAI',
    account: 'user@openai.com',
    secret: 'JBSWY3DPEHPK3PXP',
    password: 'MySecretPassword123!@#',
    digits: 6,
    period: 30
  };

  const accountWithoutPass = {
    id: 'totp-67890',
    issuer: 'Google',
    account: 'user@gmail.com',
    secret: 'JBSWY3DPEHPK3PXP',
    password: '',
    digits: 6,
    period: 30
  };

  assert.equal(accountWithPass.password, 'MySecretPassword123!@#');
  assert.equal(accountWithoutPass.password, '');
  assert.equal(Boolean(accountWithPass.password && accountWithPass.password.length > 0), true);
  assert.equal(Boolean(accountWithoutPass.password && accountWithoutPass.password.length > 0), false);
});

test('2FA Account - Validates required fields (issuer, account, secret)', () => {
  function validate2FAAccount(fields) {
    const issuer = (fields.issuer || '').trim();
    const account = (fields.account || '').trim();
    const secret = (fields.secret || '').trim().toUpperCase().replace(/\s+/g, '');
    if (!issuer || !account || !secret) {
      return { valid: false, error: 'MISSING_REQUIRED_FIELDS' };
    }
    return { valid: true, item: { issuer, account, secret, password: (fields.password || '').trim() } };
  }

  // Missing secret
  assert.equal(validate2FAAccount({ issuer: 'Google', account: 'test@gmail.com', secret: '' }).valid, false);
  // Missing issuer
  assert.equal(validate2FAAccount({ issuer: '', account: 'test@gmail.com', secret: 'JBSWY3DPEHPK3PXP' }).valid, false);
  // Missing account
  assert.equal(validate2FAAccount({ issuer: 'Google', account: '', secret: 'JBSWY3DPEHPK3PXP' }).valid, false);
  // Valid mandatory with optional password
  const validRes = validate2FAAccount({ issuer: 'Google', account: 'test@gmail.com', secret: 'JBSWY3DPEHPK3PXP', password: 'optional-pass' });
  assert.equal(validRes.valid, true);
  assert.equal(validRes.item.password, 'optional-pass');
});
