import { useState } from 'preact/hooks';
import { setSessionLock } from '../../lib/storage.js';

export function AutoLock() {
  const [m, setM] = useState(15);
  const [msg, setMsg] = useState('');
  return (
    <section>
      <h2>Auto-lock</h2>
      <input
        type="number"
        min={1}
        max={1440}
        value={m}
        onInput={(e) => setM(Number((e.target as HTMLInputElement).value))}
      />
      minutes
      <button
        style="margin-left:8px"
        onClick={async () => {
          await setSessionLock({ lastUnlockedAt: Date.now(), autoLockMinutes: m });
          setMsg('Saved.');
        }}
      >
        Save
      </button>
      {msg && <p>{msg}</p>}
    </section>
  );
}