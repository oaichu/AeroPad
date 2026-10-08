import { useState } from 'preact/hooks';
import { setSessionLock } from '../../lib/storage.js';
import { ClockIcon } from '../../popup/components/Icons.js';

export function AutoLock() {
  const [m, setM] = useState(15);
  const [msg, setMsg] = useState('');

  return (
    <div class="settings-card">
      <div class="settings-card-header">
        <h2>
          <ClockIcon size={16} />
          Auto-lock Timeout
        </h2>
      </div>
      <p class="muted">
        Automatically lock the vault after a period of browser inactivity to keep your secrets safe.
      </p>

      <div class="settings-row" style="max-width:240px;margin-top:12px">
        <input
          type="number"
          min={1}
          max={1440}
          value={m}
          onInput={(e) => setM(Number((e.target as HTMLInputElement).value))}
          style="text-align:center"
        />
        <span class="muted" style="font-weight:500">minutes</span>
      </div>

      <div class="actions-row" style="margin-top:12px">
        <button
          onClick={async () => {
            const minutes = Number.isFinite(m) ? Math.min(1440, Math.max(1, Math.round(m))) : 15;
            await setSessionLock({ lastUnlockedAt: Date.now(), autoLockMinutes: minutes });
            setMsg('Saved timeout preference.');
            setTimeout(() => setMsg(''), 2500);
          }}
        >
          Save preference
        </button>
        {msg && (
          <span class="muted" style="align-self:center;font-size:12px;margin-left:8px">
            {msg}
          </span>
        )}
      </div>
    </div>
  );
}
