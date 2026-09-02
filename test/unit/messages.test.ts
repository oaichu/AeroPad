import { describe, it, expect } from 'vitest';
import { isMessage } from '../../src/lib/messages.js';

describe('isMessage', () => {
  it('accepts unlock request', () => {
    expect(isMessage({ kind: 'unlock', password: 'x' })).toBe(true);
  });

  it('rejects unknown kind', () => {
    expect(isMessage({ kind: 'wat' })).toBe(false);
  });

  it('rejects non-object', () => {
    expect(isMessage('hello')).toBe(false);
  });
});