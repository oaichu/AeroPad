// src/lib/domain-match.ts
import type { CodeEntry } from '../types/index.js';

// Minimal two-label public-suffix list — enough to stop attacker-controlled
// lookalikes like `github.com.evil.com` or `github.co.uk.evil.com` from
// matching a `github.com` entry. A full PSL is not bundled (size cost);
// unknown multi-part suffixes degrade gracefully to last-two-label matching.
const TWO_PART_SUFFIXES: ReadonlySet<string> = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  'co.nz', 'org.nz', 'net.nz', 'ac.nz', 'govt.nz',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp', 'ed.jp',
  'co.kr', 'or.kr', 'ne.kr', 'ac.kr', 'go.kr',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'com.tw', 'org.tw', 'net.tw', 'gov.tw', 'edu.tw',
  'com.hk', 'org.hk', 'net.hk', 'gov.hk', 'edu.hk',
  'co.in', 'net.in', 'org.in', 'ac.in', 'gov.in', 'firm.in', 'gen.in', 'ind.in',
  'co.za', 'org.za', 'net.za', 'ac.za', 'gov.za',
  'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
  'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
  'co.id', 'or.id', 'ac.id', 'go.id', 'web.id', 'my.id',
  'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
  'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il',
  'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
  'com.pk', 'net.pk', 'org.pk', 'gov.pk', 'edu.pk',
  'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn', 'ac.vn',
  'com.co', 'net.co', 'org.co', 'gov.co', 'edu.co',
  'com.pe', 'net.pe', 'org.pe', 'gob.pe', 'edu.pe',
  'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'edu.ua',
  'com.pl', 'net.pl', 'org.pl', 'gov.pl', 'edu.pl',
  'com.ng', 'net.ng', 'org.ng', 'gov.ng', 'edu.ng',
  'co.ke', 'or.ke', 'ac.ke', 'go.ke',
  'co.th', 'or.th', 'ac.th', 'go.th', 'in.th',
  'com.eg', 'net.eg', 'org.eg', 'gov.eg', 'edu.eg',
  'com.sa', 'net.sa', 'org.sa', 'gov.sa', 'edu.sa',
  'com.bd', 'net.bd', 'org.bd', 'gov.bd', 'edu.bd',
]);

function hostOf(domain: string): string {
  return domain.toLowerCase().replace(/^www\./, '').split(':')[0]!.replace(/\.$/, '');
}

// Registrable domain approximation: last two labels, or last three when the
// final two are a known two-part public suffix (co.uk, com.au, ...).
export function registrableDomain(host: string): string {
  const labels = hostOf(host).split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  if (TWO_PART_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}

// Extract a domain-like token from free text (email, URL, bare host).
// Returns '' when the field contains no dotted hostname-ish token.
function domainToken(field: string): string {
  const s = field.toLowerCase().trim();
  // Strip URL scheme/userinfo if present, otherwise take the part after '@'
  // (email) or the whole string.
  const noScheme = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  const afterAt = noScheme.includes('@') ? noScheme.slice(noScheme.lastIndexOf('@') + 1) : noScheme;
  const candidate = afterAt.split(/[\s/()[\]<>]/)[0] ?? '';
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(candidate) ? candidate : '';
}

export function matchEntryForDomain(entries: CodeEntry[], domain: string): CodeEntry[] {
  const host = hostOf(domain);
  const hostReg = registrableDomain(host);
  const hostName = hostReg.split('.')[0]!; // "github" for github.com
  return entries.filter((e) => {
    if (typeof e.issuer !== 'string' || typeof e.account !== 'string') return false;
    for (const raw of [e.issuer, e.account]) {
      const field = raw.trim().toLowerCase();
      if (!field) continue;
      // Direction 1 (safe): the stored field literally contains the full
      // hostname — e.g. account "me@github.com" on "github.com". An attacker
      // on github.com.evil.com cannot satisfy this (their hostname is longer).
      if (field.includes(host)) return true;
      // Direction 2: the field carries a domain token — require the same
      // registrable domain. github.com.evil.com ≠ github.com.
      const token = domainToken(field);
      if (token && registrableDomain(token) === hostReg) return true;
      // Direction 3: bare-name issuer ("GitHub", "AWS") — must exactly equal
      // the registrable domain's own label. No prefix/substring relaxation:
      // "github-login.io" is attacker-registrable and must not match.
      if (!token && field.length >= 2 && hostName === field) return true;
    }
    return false;
  });
}
