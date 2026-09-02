import { useState } from 'preact/hooks';
import { sendMessage } from '../../lib/send-message.js';

export function ChangePassword() {
  const [oldPw, setOld] = useState('');
  const [newPw, setNew] = useState('');
  const [confirm, setConfirm] = useState('');
  const [msg, setMsg] = useState<{ text: string; kind: 'success' | 'error' } | null>(null);

  const canSubmit = oldPw.length > 0 && newPw.length >= 8 && newPw === confirm;

  return (
    <section>
      <h2>Change master password</h2>
      <p class="muted">You'll need to enter your current password to verify.</p>
      <div class="field">
        <label>Current password</label>
        <input type="password" value={oldPw} onInput={(e) => setOld((e.target as HTMLInputElement).value)} />
      </div>
      <div class="field">
        <label>New password (min 8 chars)</label>
        <input type="password" value={newPw} onInput={(e) => setNew((e.target as HTMLInputElement).value)} />
      </div>
      <div class="field">
        <label>Confirm new password</label>
        <input type="password" value={confirm} onInput={(e) => setConfirm((e.target as HTMLInputElement).value)} />
      </div>
      <div class="actions-row">
        <button
          disabled={!canSubmit}
          onClick={async () => {
            const r = await sendMessage({ kind: 'changeMasterPassword', oldPassword: oldPw, newPassword: newPw });
            setMsg(r.ok ? { text: 'Password updated.', kind: 'success' } : { text: `Failed: ${r.error}`, kind: 'error' });
            if (r.ok) { setOld(''); setNew(''); setConfirm(''); }
            setTimeout(() => setMsg(null), 3000);
          }}
        >Change</button>
        {msg && <span class={msg.kind === 'success' ? 'muted' : 'error'} style="align-self:center">{msg.text}</span>}
      </div>
    </section>
  );
}
