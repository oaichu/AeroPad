import { useEffect, useState } from 'preact/hooks';
import { loadLocale, t, type LocaleName } from '../../lib/i18n.js';

const LANGS: { code: LocaleName; name: string }[] = [
  { code: 'en', name: 'English' },
  { code: 'vi', name: 'Tiếng Việt' },
  { code: 'zh', name: '中文' },
  { code: 'ko', name: '한국어' },
  { code: 'ja', name: '日本語' },
  { code: 'es', name: 'Español' },
  { code: 'id', name: 'Bahasa Indonesia' },
  { code: 'ar', name: 'العربية' },
  { code: 'hi', name: 'हिन्दी' },
  { code: 'pt', name: 'Português' },
];

export function Language() {
  const [dict, setDict] = useState<Record<string, string>>({});
  const [cur, setCur] = useState<LocaleName>('en');
  useEffect(() => {
    let cancelled = false;
    loadLocale(cur).then((d) => { if (!cancelled) setDict(d); });
    return () => { cancelled = true; };
  }, [cur]);
  return (
    <section>
      <h2>Language</h2>
      <div class="row">
        <select
          value={cur}
          onChange={(e) => {
            const v = (e.target as HTMLSelectElement).value as LocaleName;
            setCur(v);
            if (v === 'ar') document.documentElement.setAttribute('dir', 'rtl');
            else document.documentElement.setAttribute('dir', 'ltr');
          }}
        >
          {LANGS.map((l) => (
            <option key={l.code} value={l.code}>{l.name}</option>
          ))}
        </select>
      </div>
      <p class="muted" style="margin-top:8px">Preview: {t(dict, 'app.unlock')}</p>
    </section>
  );
}
