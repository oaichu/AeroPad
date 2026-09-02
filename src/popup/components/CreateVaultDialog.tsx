import { useState } from 'preact/hooks';
import type { Response } from '../../lib/messages.js';

interface Props {
  onSubmit: (pw: string) => Promise<Response>;
}

export function CreateVaultDialog({ onSubmit }: Props) {
  const [pw, setPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const tooShort = pw.length > 0 && pw.length < 8;
  const mismatch = confirm.length > 0 && pw !== confirm;
  const disabled = busy || pw.length < 8 || pw !== confirm;

  return (
    <div>
      <h2>Create your vault</h2>
      <p class="muted" style="margin-top:0">
        Choose a master password. You'll need it every time you open AeroPad.
        It cannot be recovered if you forget it.
      </p>
      <input
        type="password"
        placeholder="Master password (min 8 chars)"
        value={pw}
        onInput={(e) => setPw((e.target as HTMLInputElement).value)}
      />
      <input
        style="margin-top:6px"
        type="password"
        placeholder="Confirm password"
        value={confirm}
        onInput={(e) => setConfirm((e.target as HTMLInputElement).value)}
      />
      {tooShort && <p class="error">Password must be at least 8 characters.</p>}
      {mismatch && <p class="error">Passwords don't match.</p>}
      <button
        style="margin-top:8px"
        disabled={disabled}
        onClick={async () => {
          setBusy(true);
          setErr(null);
          const r = await onSubmit(pw);
          setBusy(false);
          if (!r.ok) setErr(r.error);
        }}
      >
        Create vault
      </button>
      {err && <p class="error">{err}</p>}
    </div>
  );
}
