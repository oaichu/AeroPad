import { useState } from 'preact/hooks';
import type { Response } from '../../lib/messages.js';

interface Props { onSubmit: (pw: string) => Promise<Response>; }

export function UnlockDialog({ onSubmit }: Props) {
  const [pw, setPw] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div>
      <h2>AeroPad</h2>
      <input
        type="password"
        placeholder="Master password"
        value={pw}
        onInput={(e) => setPw((e.target as HTMLInputElement).value)}
      />
      <button
        disabled={busy || pw.length < 1}
        onClick={async () => {
          setBusy(true); setErr(null);
          const r = await onSubmit(pw);
          setBusy(false);
          if (!r.ok) setErr(r.error === 'wrong_password' ? 'Wrong password' : r.error);
        }}
      >
        Unlock
      </button>
      {err && <p class="error">{err}</p>}
    </div>
  );
}