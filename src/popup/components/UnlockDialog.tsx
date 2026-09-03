import { useState } from 'preact/hooks';
import type { Response } from '../../lib/messages.js';
import { ShieldIcon, LockIcon, EyeIcon, EyeOffIcon } from './Icons.js';

interface Props {
  onSubmit: (pw: string) => Promise<Response>;
}

export function UnlockDialog({ onSubmit }: Props) {
  const [pw, setPw] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  return (
    <div style="padding: 10px 4px">
      <div style="text-align:center;margin-bottom:20px">
        <div style="display:inline-flex;align-items:center;justify-content:center;width:48px;height:48px;border-radius:var(--radius-lg);background:var(--accent-gradient);color:white;box-shadow:0 4px 14px var(--accent-glow);margin-bottom:12px">
          <ShieldIcon size={24} />
        </div>
        <h1 style="font-size:18px;margin-bottom:4px">AeroPad</h1>
        <p class="muted">Enter your master password to unlock your vault.</p>
      </div>

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
        <label for="master-pw-input">
          Master password
        </label>
        <div class="password-field-wrap">
          <input
            id="master-pw-input"
            aria-label="Master password"
            type={showPw ? 'text' : 'password'}
            autoFocus
            value={pw}
            onInput={(e) => setPw((e.target as HTMLInputElement).value)}
            placeholder="Enter password"
          />
          <button
            type="button"
            class="password-toggle-btn"
            onClick={() => setShowPw(!showPw)}
            aria-label={showPw ? 'Hide password' : 'Show password'}
            tabIndex={-1}
          >
            {showPw ? <EyeOffIcon size={16} /> : <EyeIcon size={16} />}
          </button>
        </div>

        {err && <p class="error">{err}</p>}

        <div class="bottom-dock" style="margin-top:16px">
          <button type="submit" disabled={!pw || busy}>
            <LockIcon size={14} />
            {busy ? 'Unlocking…' : 'Unlock'}
          </button>
        </div>
      </form>

      <div style="margin-top:24px;padding:10px 12px;border-radius:var(--radius-sm);background:var(--hover);border:1px solid var(--border)">
        <p class="muted" style="margin:0;font-size:11px;line-height:1.4">
          Lost your password? The vault cannot be recovered — restore from a <code>.aeropad</code> backup instead.
        </p>
      </div>
    </div>
  );
}
