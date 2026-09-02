import { useState } from 'preact/hooks';
import { setSessionLock } from '../../lib/storage.js';

export function AutoLock() {
  const [m, setM] = useState(15);
  const [msg, setMsg] = useState('');
  return (
    <section>
      <h2>Auto-lock</h2>
      <p class="muted">Lock the vault automatically after this many minutes of inactivity.</p>
      <div class="row">
        <input
          type="number"
          min={1}
          max={1440}
          value={m}
          onInput={(e) => setM(Number((e.target as HTMLInputElement).value))}
        />
        <span class="muted">minutes</span>
      </div>
      <div class="actions-row">
        <button
          onClick={async () => {
            await setSessionLock({ lastUnlockedAt: Date.now(), autoLockMinutes: m });
            setMsg('Saved.');
            setTimeout(() => setMsg(''), 2000);
          }}
        >Save</button>
        {msg && <span class="muted" style="align-self:center">{msg}</span>}
      </div>
    </section>
  );
}
