import { useState } from 'preact/hooks';
import { sendMessage } from '../../lib/send-message.js';
import { KeyIcon } from '../../popup/components/Icons.js';

export function ChangePassword() {
  const [oldPw, setOld] = useState('');
  const [newPw, setNew] = useState('');
  const [confirm, setConfirm] = useState('');
  const [msg, setMsg] = useState<{ text: string; kind: 'success' | 'error' } | null>(null);

  const canSubmit = oldPw.length > 0 && newPw.length >= 8 && newPw === confirm;

  return (
    <div class="settings-card">
      <div class="settings-card-header">
        <h2>
          <KeyIcon size={16} />
          Change Master Password
        </h2>
      </div>
      <p class="muted">You must enter your current password to re-encrypt your vault with a new key.</p>

      <div style="display:flex;flex-direction:column;gap:10px;margin-top:14px;max-width:420px">
        <div>
          <label>Current password</label>
          <input
            type="password"
            value={oldPw}
            onInput={(e) => setOld((e.target as HTMLInputElement).value)}
            placeholder="Current master password"
          />
        </div>
        <div>
          <label>New password (min 8 chars)</label>
          <input
            type="password"
            value={newPw}
            onInput={(e) => setNew((e.target as HTMLInputElement).value)}
            placeholder="New master password"
          />
        </div>
        <div>
          <label>Confirm new password</label>
          <input
            type="password"
            value={confirm}
            onInput={(e) => setConfirm((e.target as HTMLInputElement).value)}
            placeholder="Confirm new master password"
          />
        </div>

        <div class="actions-row" style="margin-top:6px">
          <button
            disabled={!canSubmit}
            onClick={async () => {
              const r = await sendMessage({
                kind: 'changeMasterPassword',
                oldPassword: oldPw,
                newPassword: newPw,
              });
              setMsg(r.ok ? { text: 'Password updated successfully.', kind: 'success' } : { text: `Failed: ${r.error}`, kind: 'error' });
              if (r.ok) { setOld(''); setNew(''); setConfirm(''); }
              setTimeout(() => setMsg(null), 3000);
            }}
          >
            Update password
          </button>
          {msg && (
            <span
              class={msg.kind === 'success' ? 'muted' : 'error'}
              style="align-self:center;margin-left:8px;font-size:12px"
            >
              {msg.text}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
