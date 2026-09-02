import { useState } from 'preact/hooks';
import type { Response } from '../../lib/messages.js';

interface Props { onSubmit: (pw: string) => Promise<Response>; }

export function UnlockDialog({ onSubmit }: Props) {
  const [pw, setPw] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div>
      <div class="header">
        <h1>🔐 AeroPad</h1>
      </div>
      <p class="muted">Enter your master password to unlock your vault.</p>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          if (!pw || busy) return;
          setBusy(true); setErr(null);
          const r = await onSubmit(pw);
          setBusy(false);
          if (!r.ok) setErr(r.error === 'wrong_password' ? 'Wrong password.' : r.error);
        }}
      >
        <label style="margin-top:8px">
          Master password
          <input
            type="password"
            autoFocus
            value={pw}
            onInput={(e) => setPw((e.target as HTMLInputElement).value)}
            style="margin-top:4px"
          />
        </label>
        {err && <p class="error">{err}</p>}
        <div class="actions" style="margin-top:12px">
          <button class="grow" type="submit" disabled={!pw || busy}>Unlock</button>
        </div>
      </form>
      <p class="muted" style="margin-top:16px;font-size:11px">
        Lost your password? The vault cannot be recovered — restore from a <code>.aeropad</code> backup instead.
      </p>
    </div>
  );
}
