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

  // --- Anti-phishing: attacker-controlled lookalike hosts must NOT match ---

  it('rejects subdomain-suffix phishing host (github.com.evil.com)', () => {
    expect(matchEntryForDomain([make('GitHub')], 'github.com.evil.com')).toEqual([]);
    expect(matchEntryForDomain([make('Work', 'me@github.com')], 'github.com.evil.com')).toEqual([]);
  });

  it('rejects prefix-squat host (github-login.io)', () => {
    expect(matchEntryForDomain([make('GitHub')], 'github-login.io')).toEqual([]);
    expect(matchEntryForDomain([make('GitHub')], 'secure-github.com')).toEqual([]);
  });

  it('does not let short issuers match arbitrary hosts containing them', () => {
    // Old behavior: host.includes(issuer) → "digital.com".includes("git") matched.
    expect(matchEntryForDomain([make('git')], 'digital.com')).toEqual([]);
    expect(matchEntryForDomain([make('mail')], 'hotmail.com')).toEqual([]);
    expect(matchEntryForDomain([make('o')], 'evil.com')).toEqual([]);
  });

  it('still matches subdomains of the same registrable domain', () => {
    expect(matchEntryForDomain([make('GitHub')], 'gist.github.com').map((e) => e.issuer)).toEqual(['GitHub']);
    expect(matchEntryForDomain([make('Work', 'me@github.com')], 'mail.github.com').map((e) => e.issuer)).toEqual(['Work']);
  });

  it('handles two-part public suffixes (co.uk)', () => {
    expect(matchEntryForDomain([make('ExampleBank')], 'examplebank.co.uk.evil.com')).toEqual([]);
    expect(matchEntryForDomain([make('ExampleBank')], 'login.examplebank.co.uk').map((e) => e.issuer)).toEqual(['ExampleBank']);
  });

  it('matches URL/email fields only on registrable-domain equality', () => {
    expect(matchEntryForDomain([make('X', 'https://github.com/settings')], 'github.com').map((e) => e.issuer)).toEqual(['X']);
    expect(matchEntryForDomain([make('X', 'https://github.com/settings')], 'github.com.evil.com')).toEqual([]);
  });
});