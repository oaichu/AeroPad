import { useEffect, useState } from 'preact/hooks';
import { loadLocale, t, type LocaleName } from '../../lib/i18n.js';

const LANGS: LocaleName[] = ['en', 'vi', 'zh', 'ko', 'ja', 'es', 'id', 'ar', 'hi', 'pt'];

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
      <select
        value={cur}
        onChange={(e) => setCur((e.target as HTMLSelectElement).value as LocaleName)}
      >
        {LANGS.map((l) => (
          <option key={l} value={l}>{l}</option>
        ))}
      </select>
      <p style="margin-top:8px">{t(dict, 'app.unlock')}</p>
    </section>
  );
}