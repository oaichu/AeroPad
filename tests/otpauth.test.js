import test from 'node:test';
import assert from 'node:assert/strict';
import { buildOTPAuthURI, parseOTPAuthURI } from '../src/crypto/otpauth.js';

test('OTPAuth - Builds standard Google Authenticator URI correctly', () => {
  const uri = buildOTPAuthURI({
    issuer: 'Binance',
    account: 'trader@web3.io',
    secret: 'JBSWY3DPEHPK3PXP',
    digits: 6,
    period: 30
  });

  assert.equal(
    uri,
    'otpauth://totp/Binance:trader%40web3.io?secret=JBSWY3DPEHPK3PXP&issuer=Binance&algorithm=SHA1&digits=6&period=30'
  );
});

test('OTPAuth - Parses standard otpauth URI with colon label and query params', () => {
  const input = 'otpauth://totp/Google:user%40gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google&digits=6&period=30';
  const parsed = parseOTPAuthURI(input);

  assert.equal(parsed.isValid, true);
  assert.equal(parsed.issuer, 'Google');
  assert.equal(parsed.account, 'user@gmail.com');
  assert.equal(parsed.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(parsed.digits, 6);
  assert.equal(parsed.period, 30);
});

test('OTPAuth - Parses direct Base32 secret string gracefully', () => {
  const directSecret = 'JBSW Y3DP-EHPK 3PXP';
  const parsed = parseOTPAuthURI(directSecret);

  assert.equal(parsed.isValid, true);
  assert.equal(parsed.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(parsed.issuer, 'Direct Key');
});

test('OTPAuth - Flags invalid or empty input as invalid', () => {
  const parsed1 = parseOTPAuthURI('');
  assert.equal(parsed1.isValid, false);

  const parsed2 = parseOTPAuthURI('http://invalid-url.com');
  assert.equal(parsed2.isValid, false);
});

test('OTPAuth - Preserves non-default digits, period and algorithm from URI', () => {
  // Regression: a decoded account must keep its real parameters — the vault
  // computes codes from them, defaults produce permanently wrong codes.
  const input = 'otpauth://totp/Vault:user@web3.io?secret=JBSWY3DPEHPK3PXP&issuer=Vault&digits=8&period=60&algorithm=SHA256';
  const parsed = parseOTPAuthURI(input);

  assert.equal(parsed.isValid, true);
  assert.equal(parsed.digits, 8);
  assert.equal(parsed.period, 60);
  assert.equal(parsed.algo, 'SHA256');
});

test('OTPAuth - Build includes algorithm parameter so QR imports match the generator selection', () => {
  const uri = buildOTPAuthURI({ issuer: 'A', account: 'b@c.io', secret: 'JBSWY3DPEHPK3PXP', algo: 'SHA256' });
  assert.ok(uri.includes('algorithm=SHA256'));
});
