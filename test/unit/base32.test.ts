import { describe, it, expect } from 'vitest';
import { base32Decode } from '../../src/lib/base32.js';

describe('base32Decode', () => {
  it('decodes RFC 4648 test vector', () => {
    expect(Array.from(base32Decode('JBSWY3DPEHPK3PXP'))).toEqual([
      0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef,
    ]);
  });

  it('is case-insensitive', () => {
    expect(Array.from(base32Decode('jbswy3dpehpk3pxp'))).toEqual(Array.from(base32Decode('JBSWY3DPEHPK3PXP')));
  });

  it('ignores padding', () => {
    expect(Array.from(base32Decode('JBSWY3DPEHPK3PXP===='))).toEqual(Array.from(base32Decode('JBSWY3DPEHPK3PXP')));
  });

  it('throws on invalid character', () => {
    expect(() => base32Decode('JBSW!3DPEHPK3PXP')).toThrow();
  });
});