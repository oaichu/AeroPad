// src/lib/i18n.ts
export type LocaleName = 'en' | 'vi' | 'zh' | 'ko' | 'ja' | 'es' | 'id' | 'ar' | 'hi' | 'pt';

const RTL_LOCALES = new Set<LocaleName>(['ar']);

const cache = new Map<LocaleName, Record<string, string>>();

export async function loadLocale(name: LocaleName): Promise<Record<string, string>> {
  if (cache.has(name)) return cache.get(name)!;
  // We also support bundled JSON via dynamic import for tests
  let dict: Record<string, string>;
  try {
    const mod = await import(`../locales/${name}.json`);
    dict = mod.default as Record<string, string>;
  } catch {
    const url = chrome.runtime.getURL(`_locales/${name}/messages.json`);
    const res = await fetch(url);
    dict = await res.json();
  }
  cache.set(name, dict);
  return dict;
}

export function t(dict: Record<string, string>, key: string, vars?: Record<string, string | number>): string {
  let s = dict[key] ?? key;
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.replaceAll(`{${k}}`, String(v));
  return s;
}

export function isRTL(name: string): boolean {
  return RTL_LOCALES.has(name as LocaleName);
}