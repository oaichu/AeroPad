import { useEffect, useState } from 'preact/hooks';
import { UnlockDialog } from './components/UnlockDialog.js';
import { sendMessage } from '../lib/send-message.js';

export function App() {
  const [unlocked, setUnlocked] = useState<boolean | null>(null);
  useEffect(() => {
    sendMessage({ kind: 'isUnlocked' }).then((r) => {
      if (r.ok) setUnlocked(r.data === true);
    });
  }, []);

  if (unlocked === null) return <p class="muted">loading…</p>;
  if (!unlocked) return <UnlockDialog onSubmit={async (pw) => {
    const r = await sendMessage({ kind: 'unlock', password: pw });
    if (r.ok) setUnlocked(true);
    return r;
  }} />;
  return <div><h2>AeroPad</h2><p class="muted">Codes & notes will appear here.</p></div>;
}