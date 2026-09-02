import { describe, it, expect } from 'vitest';
import type { CodeEntry, Vault, VaultBlob } from '../../src/types/index.js';
import { isCodeEntry, isVault } from '../../src/types/index.js';

describe('types', () => {
  it('isCodeEntry accepts valid entry', () => {
    const e: CodeEntry = {
      id: '1', issuer: 'GitHub', account: 'me@x.com',
      secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, createdAt: 0,
    };
    expect(isCodeEntry(e)).toBe(true);
  });

  it('isCodeEntry rejects missing fields', () => {
    expect(isCodeEntry({ id: '1' })).toBe(false);
  });

  it('isVault accepts empty vault', () => {
    expect(isVault({ codes: [], notes: [] })).toBe(true);
  });
});