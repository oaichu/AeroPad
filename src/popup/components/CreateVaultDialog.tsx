import { useState } from 'preact/hooks';
import type { Response } from '../../lib/messages.js';

interface Props { onSubmit: (pw: string) => Promise<Response>; }

function strength(pw: string): { score: 0 | 1 | 2 | 3 | 4; label: string } {
  if (pw.length < 8) return { score: 0, label: 'too short' };
  let s: 0 | 1 | 2 | 3 | 4 = 0;
  if (pw.length >= 12) s = (s + 1) as 0 | 1 | 2 | 3 | 4;
  if (/[A-Z]/.test(pw)) s = (s + 1) as 0 | 1 | 2 | 3 | 4;
  if (/[0-9]/.test(pw)) s = (s + 1) as 0 | 1 | 2 | 3 | 4;
  if (/[^A-Za-z0-9]/.test(pw)) s = (s + 1) as 0 | 1 | 2 | 3 | 4;
  const labels = ['weak', 'fair', 'good', 'strong', 'excellent'];
  return { score: s, label: labels[s]! };
}

export function CreateVaultDialog({ onSubmit }: Props) {
  const [pw, setPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const tooShort = pw.length > 0 && pw.length < 8;
  const mismatch = confirm.length > 0 && pw !== confirm;
  const disabled = busy || pw.length < 8 || pw !== confirm;
  const s = strength(pw);

  return (
    <div>
      <div class="header">
        <h1>🔐 AeroPad</h1>
      </div>
      <p class="muted">Create your vault. Choose a master password — it cannot be recovered if you forget it.</p>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          if (disabled) return;
          setBusy(true); setErr(null);
          const r = await onSubmit(pw);
          setBusy(false);
          if (!r.ok) setErr(r.error);
        }}
      >
        <label>Master password (min 8 chars)</label>
        <input
          type="password"
          autoFocus
          value={pw}
          onInput={(e) => setPw((e.target as HTMLInputElement).value)}
        />
        {pw.length > 0 && (
          <div style="display:flex;gap:3px;margin:4px 0">
            {[0, 1, 2, 3].map((i) => (
              <div
                key={i}
                style={`flex:1;height:3px;border-radius:2px;background:${i < s.score ? (s.score <= 1 ? 'var(--danger)' : s.score === 2 ? '#d97706' : 'var(--success)') : 'var(--border)'}`}
              />
            ))}
            <span class="muted" style="font-size:11px;margin-left:4px">{s.label}</span>
          </div>
        )}
        <label>Confirm password</label>
        <input
          type="password"
          value={confirm}
          onInput={(e) => setConfirm((e.target as HTMLInputElement).value)}
        />
        {tooShort && <p class="error">Password must be at least 8 characters.</p>}
        {mismatch && <p class="error">Passwords don't match.</p>}
        {err && <p class="error">{err}</p>}
        <div class="actions" style="margin-top:12px">
          <button class="grow" type="submit" disabled={disabled}>{busy ? 'Creating…' : 'Create vault'}</button>
        </div>
      </form>
    </div>
  );
}
