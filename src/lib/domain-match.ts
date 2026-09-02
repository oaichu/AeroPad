// src/lib/domain-match.ts
import type { CodeEntry } from '../types/index.js';

function hostOf(domain: string): string {
  return domain.toLowerCase().replace(/^www\./, '').split(':')[0]!;
}

export function matchEntryForDomain(entries: CodeEntry[], domain: string): CodeEntry[] {
  const host = hostOf(domain);
  return entries.filter((e) => {
    const i = e.issuer.toLowerCase();
    const a = e.account.toLowerCase();
    return (i.length > 0 && host.includes(i))
      || (a.length > 0 && host.includes(a))
      || i.includes(host)
      || a.includes(host);
  });
}