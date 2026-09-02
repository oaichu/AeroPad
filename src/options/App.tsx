import { useState } from 'preact/hooks';
import { ImportExport } from './components/ImportExport.js';
import { ChangePassword } from './components/ChangePassword.js';
import { Language } from './components/Language.js';
import { AutoLock } from './components/AutoLock.js';
import { sendMessage } from '../lib/send-message.js';

export function App() {
  const [busy, setBusy] = useState(false);
  return (
    <div style="max-width:680px;margin:0 auto;padding:24px 20px 80px">
      <div class="header" style="margin-bottom:8px">
        <h1>⚙ AeroPad Settings</h1>
      </div>
      <p class="muted" style="margin-bottom:8px">Manage your vault, language, and security.</p>
      <ImportExport />
      <ChangePassword />
      <Language />
      <AutoLock />
      <section>
        <h2>Lock</h2>
        <p class="muted">Lock the vault now. You'll need to enter your master password to unlock it again.</p>
        <div class="actions-row">
          <button
            class="secondary"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              await sendMessage({ kind: 'lock' });
              location.reload();
            }}
          >Lock now</button>
        </div>
      </section>
    </div>
  );
}
