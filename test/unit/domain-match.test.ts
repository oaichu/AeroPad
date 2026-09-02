import { describe, it, expect } from 'vitest';
import { matchEntryForDomain } from '../../src/lib/domain-match.js';
import type { CodeEntry } from '../../src/types/index.js';

const make = (issuer: string, account = ''): CodeEntry => ({
  id: issuer, issuer, account, secret: 'JBSWY3DPEHPK3PXP',
  algorithm: 'SHA1', digits: 6, period: 30, createdAt: 0,
});

describe('matchEntryForDomain', () => {
  it('matches by issuer substring (case-insensitive)', () => {
    expect(matchEntryForDomain([make('GitHub')], 'github.com').map((e) => e.issuer)).toEqual(['GitHub']);
  });

  it('matches by account substring', () => {
    expect(matchEntryForDomain([make('Work', 'me@github.com')], 'github.com').map((e) => e.issuer)).toEqual(['Work']);
  });

  it('returns empty when no match', () => {
    expect(matchEntryForDomain([make('Google')], 'github.com')).toEqual([]);
  });

  it('returns multiple when ambiguous', () => {
    const r = matchEntryForDomain([make('GitHub'), make('Work', 'a@github.com')], 'github.com');
    expect(r.length).toBe(2);
  });
});