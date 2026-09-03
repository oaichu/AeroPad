import { useState } from 'preact/hooks';
import { ImportExport } from './components/ImportExport.js';
import { ChangePassword } from './components/ChangePassword.js';
import { Language } from './components/Language.js';
import { AutoLock } from './components/AutoLock.js';
import { sendMessage } from '../lib/send-message.js';
import { ShieldIcon, LockIcon } from '../popup/components/Icons.js';

export function App() {
  const [busy, setBusy] = useState(false);

  return (
    <div class="settings-wrapper">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
        <div class="brand-icon" style="width:38px;height:38px">
          <ShieldIcon size={20} />
        </div>
        <div>
          <h1 style="font-size:20px;margin:0">AeroPad Settings</h1>
          <p class="muted" style="margin:2px 0 0">Local-first encrypted vault & 2FA authenticator configuration</p>
        </div>
      </div>

      <div class="settings-grid">
        <div style="display:flex;flex-direction:column;gap:16px">
          <ImportExport />
          <AutoLock />
          <Language />
        </div>

        <div style="display:flex;flex-direction:column;gap:16px">
          <ChangePassword />
          <div class="settings-card" style="border-color:rgba(239,68,68,0.25)">
            <div class="settings-card-header">
              <h2 style="color:var(--danger)">
                <LockIcon size={16} />
                Lock Vault
              </h2>
            </div>
            <p class="muted">
              Immediately lock the vault in memory. You will need your master password to unlock and decrypt your credentials.
            </p>
            <div class="actions-row">
              <button
                class="danger"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  await sendMessage({ kind: 'lock' });
                  location.reload();
                }}
              >
                {busy ? 'Locking…' : 'Lock now'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
