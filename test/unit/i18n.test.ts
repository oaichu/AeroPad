import { describe, it, expect } from 'vitest';
import { loadLocale, t, isRTL } from '../../src/lib/i18n.js';

describe('i18n', () => {
  it('t substitutes variables', () => {
    expect(t({ greet: 'Hello, {name}!' }, 'greet', { name: 'Ada' })).toBe('Hello, Ada!');
  });

  it('t returns key when missing', () => {
    expect(t({}, 'missing.key')).toBe('missing.key');
  });

  it('isRTL true for ar', () => {
    expect(isRTL('ar')).toBe(true);
    expect(isRTL('en')).toBe(false);
  });

  it('loadLocale resolves with keys', async () => {
    const dict = await loadLocale('en');
    expect(typeof dict['app.unlock']).toBe('string');
  });
});