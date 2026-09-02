import { describe, it, expect } from 'vitest';
import {
  randomBytes, deriveKey, encrypt, decrypt,
  bytesToBase64Url, base64UrlToBytes,
} from '../../src/lib/crypto.js';

describe('crypto helpers', () => {
  it('randomBytes returns the requested length', () => {
    expect(randomBytes(16).length).toBe(16);
    expect(randomBytes(0).length).toBe(0);
  });

  it('base64url round-trips', () => {
    const b = new Uint8Array([0, 1, 2, 250, 251, 255]);
    const s = bytesToBase64Url(b);
    expect(s).not.toMatch(/[+/=]/);
    expect(Array.from(base64UrlToBytes(s))).toEqual(Array.from(b));
  });
});

describe('AES-GCM round-trip', () => {
  it('encrypts and decrypts arbitrary bytes', async () => {
    const salt = randomBytes(16);
    const key = await deriveKey('correct horse battery staple', salt, 1000); // fast for tests
    const plaintext = new TextEncoder().encode('hello world');
    const { iv, ciphertext } = await encrypt(plaintext, key);
    const decrypted = await decrypt(ciphertext, iv, key);
    expect(new TextDecoder().decode(decrypted)).toBe('hello world');
  });

  it('rejects tampered ciphertext', async () => {
    const salt = randomBytes(16);
    const key = await deriveKey('pw', salt, 1000);
    const { iv, ciphertext } = await encrypt(new TextEncoder().encode('x'), key);
    ciphertext[0]! ^= 0xff;
    await expect(decrypt(ciphertext, iv, key)).rejects.toThrow();
  });
});