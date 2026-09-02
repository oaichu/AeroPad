import { useState } from 'preact/hooks';
import { ImportExport } from './components/ImportExport.js';
import { ChangePassword } from './components/ChangePassword.js';
import { Language } from './components/Language.js';
import { AutoLock } from './components/AutoLock.js';
import { sendMessage } from '../lib/send-message.js';

export function App() {
  const [busy, setBusy] = useState(false);
  return (
    <div style="max-width:720px;margin:24px auto;padding:0 16px">
      <h1>AeroPad Settings</h1>
      <ImportExport />
      <ChangePassword />
      <Language />
      <AutoLock />
      <button
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          await sendMessage({ kind: 'lock' });
          location.reload();
        }}
      >
        Lock now
      </button>
    </div>
  );
}