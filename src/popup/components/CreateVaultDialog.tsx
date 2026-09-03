import { useState } from 'preact/hooks';
import type { Response } from '../../lib/messages.js';
import { ShieldIcon, LockIcon, EyeIcon, EyeOffIcon, CheckIcon } from './Icons.js';

interface Props {
  onSubmit: (pw: string) => Promise<Response>;
}

function strength(pw: string): { score: 0 | 1 | 2 | 3 | 4; label: string; color: string } {
  if (pw.length < 8) return { score: 0, label: 'Too short (min 8)', color: 'var(--danger)' };
  let s: 0 | 1 | 2 | 3 | 4 = 0;
  if (pw.length >= 12) s = (s + 1) as 0 | 1 | 2 | 3 | 4;
  if (/[A-Z]/.test(pw)) s = (s + 1) as 0 | 1 | 2 | 3 | 4;
  if (/[0-9]/.test(pw)) s = (s + 1) as 0 | 1 | 2 | 3 | 4;
  if (/[^A-Za-z0-9]/.test(pw)) s = (s + 1) as 0 | 1 | 2 | 3 | 4;
  const labels = ['Weak', 'Fair', 'Good', 'Strong', 'Excellent'];
  const colors = ['var(--danger)', 'var(--warning)', '#eab308', 'var(--success)', '#059669'];
  return { score: s, label: labels[s]!, color: colors[s]! };
}

export function CreateVaultDialog({ onSubmit }: Props) {
  const [pw, setPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const tooShort = pw.length > 0 && pw.length < 8;
  const mismatch = confirm.length > 0 && pw !== confirm;
  const disabled = busy || pw.length < 8 || pw !== confirm;
  const s = strength(pw);

  return (
    <div style="padding: 10px 4px">
      <div style="text-align:center;margin-bottom:18px">
        <div style="display:inline-flex;align-items:center;justify-content:center;width:48px;height:48px;border-radius:var(--radius-lg);background:var(--accent-gradient);color:white;box-shadow:0 4px 14px var(--accent-glow);margin-bottom:12px">
          <ShieldIcon size={24} />
        </div>
        <h1 style="font-size:18px;margin-bottom:4px">Create Your Vault</h1>
        <p class="muted">Set a master password. It encrypts all your keys locally and cannot be recovered if forgotten.</p>
      </div>

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
        <label for="create-pw">
          Master password (min 8 chars)
          {pw.length > 0 && (
            <span style={`font-size:11px;font-weight:600;color:${s.color}`}>{s.label}</span>
          )}
        </label>
        <div class="password-field-wrap">
          <input
            id="create-pw"
            type={showPw ? 'text' : 'password'}
            autoFocus
            value={pw}
            onInput={(e) => setPw((e.target as HTMLInputElement).value)}
            placeholder="Choose a strong password"
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

        {pw.length > 0 && (
          <div class="strength-meter">
            {[0, 1, 2, 3].map((i) => (
              <div
                key={i}
                class="strength-bar"
                style={`background:${i < s.score ? s.color : 'var(--border)'}`}
              />
            ))}
          </div>
        )}

        <label for="create-confirm-pw" style="margin-top:12px">
          Confirm password
          {confirm.length > 0 && !mismatch && pw.length >= 8 && (
            <span style="font-size:11px;color:var(--success);display:flex;align-items:center;gap:3px">
              <CheckIcon size={12} /> Match
            </span>
          )}
        </label>
        <input
          id="create-confirm-pw"
          type={showPw ? 'text' : 'password'}
          value={confirm}
          onInput={(e) => setConfirm((e.target as HTMLInputElement).value)}
          placeholder="Re-enter password"
        />

        {tooShort && <p class="error">Password must be at least 8 characters.</p>}
        {mismatch && <p class="error">Passwords don't match.</p>}
        {err && <p class="error">{err}</p>}

        <div class="bottom-dock" style="margin-top:16px">
          <button type="submit" disabled={disabled}>
            <LockIcon size={14} />
            {busy ? 'Creating vault…' : 'Create vault'}
          </button>
        </div>
      </form>
    </div>
  );
}
