import { useEffect, useState } from 'preact/hooks';
import { loadLocale, t, type LocaleName } from '../../lib/i18n.js';
import { SettingsIcon } from '../../popup/components/Icons.js';

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
    <div class="settings-card">
      <div class="settings-card-header">
        <h2>
          <SettingsIcon size={16} />
          Display Language
        </h2>
      </div>
      <p class="muted">Select your preferred interface language for AeroPad.</p>

      <div class="settings-row" style="max-width:320px;margin-top:12px">
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

      <div style="margin-top:10px;padding:8px 12px;border-radius:var(--radius-sm);background:var(--hover);border:1px solid var(--border);display:inline-block">
        <span class="muted" style="font-size:12px">
          Preview: <strong style="color:var(--fg)">{t(dict, 'app.unlock')}</strong>
        </span>
      </div>
    </div>
  );
}
