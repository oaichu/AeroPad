import test from 'node:test';
import assert from 'node:assert/strict';
import { Base32 } from '../src/crypto/base32.js';

test('Base32 - Decodes standard RFC 4648 test vectors', () => {
  // RFC 4648 test vectors
  // "" -> ""
  // "f" -> "MY======"
  // "fo" -> "MZXQ===="
  // "foo" -> "MZXW6==="
  // "foob" -> "MZXW6YQ="
  // "fooba" -> "MZXW6YTB"
  // "foobar" -> "MZXW6YTBOI======"

  const textDecoder = new TextDecoder();

  const buf1 = Base32.decode('MY======');
  assert.equal(textDecoder.decode(buf1), 'f');

  const buf2 = Base32.decode('MZXQ====');
  assert.equal(textDecoder.decode(buf2), 'fo');

  const buf3 = Base32.decode('MZXW6===');
  assert.equal(textDecoder.decode(buf3), 'foo');

  const buf4 = Base32.decode('MZXW6YTBOI======');
  assert.equal(textDecoder.decode(buf4), 'foobar');
});

test('Base32 - Handles lowercase, spaces, and dashes cleanly', () => {
  const textDecoder = new TextDecoder();
  const raw = 'mzxw 6ytb-oi===';
  const buf = Base32.decode(raw);
  assert.equal(textDecoder.decode(buf), 'foobar');
});

test('Base32 - Encodes buffer back to Base32 string', () => {
  const textEncoder = new TextEncoder();
  const encoded = Base32.encode(textEncoder.encode('foobar'));
  assert.equal(encoded, 'MZXW6YTBOI');
});

test('Base32 - Generates cryptographically secure random secrets', () => {
  const secretDefault = Base32.randomSecret();
  assert.equal(secretDefault.length, 32);
  assert.match(secretDefault, /^[A-Z2-7]{32}$/);

  const secret16 = Base32.randomSecret(16);
  assert.equal(secret16.length, 16);
  assert.match(secret16, /^[A-Z2-7]{16}$/);

  const secret32 = Base32.randomSecret(32);
  assert.equal(secret32.length, 32);
  assert.match(secret32, /^[A-Z2-7]{32}$/);
});
