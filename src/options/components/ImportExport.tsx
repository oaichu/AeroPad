import { useState } from 'preact/hooks';
import { sendMessage } from '../../lib/send-message.js';
import { ShieldIcon } from '../../popup/components/Icons.js';

export function ImportExport() {
  const [msg, setMsg] = useState<{ text: string; kind: 'success' | 'error' } | null>(null);

  return (
    <div class="settings-card">
      <div class="settings-card-header">
        <h2>
          <ShieldIcon size={16} />
          Vault Backup & Restore
        </h2>
      </div>
      <p class="muted">
        Export your encrypted vault to a portable <code>.aeropad</code> backup file. Importing will replace or merge with your current vault.
      </p>
      <div class="actions-row" style="margin-top:14px">
        <button
          onClick={async () => {
            const pw = prompt('Set a password for this backup (min 8 characters):') ?? '';
            if (pw.length < 8) {
              setMsg({ text: 'Export cancelled: a password of at least 8 characters is required.', kind: 'error' });
              setTimeout(() => setMsg(null), 3000);
              return;
            }
            const r = await sendMessage({ kind: 'exportAeropad', password: pw });
            if (r.ok && typeof r.data === 'string') {
              const blob = new Blob([r.data], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `aeropad-${new Date().toISOString().slice(0, 10)}.aeropad`;
              a.click();
              URL.revokeObjectURL(url);
              setMsg({ text: 'Backup exported successfully.', kind: 'success' });
            } else {
              setMsg({ text: `Export failed: ${r.ok ? 'no data' : r.error}`, kind: 'error' });
            }
            setTimeout(() => setMsg(null), 3000);
          }}
        >
          Export .aeropad
        </button>

        <label class="secondary" style="position:relative;display:inline-flex;align-items:center;padding:8px 14px;border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-weight:500;font-size:13px;margin:0">
          Import .aeropad…
          <input
            type="file"
            accept=".aeropad,application/json"
            class="visually-hidden-file"
            onChange={async (e) => {
              const file = (e.target as HTMLInputElement).files?.[0];
              if (!file) return;
              const json = await file.text();
              const pw = prompt('Password for this backup (empty if none):') ?? '';
              const r = await sendMessage({ kind: 'importAeropad', json, password: pw, strategy: 'replace' });
              setMsg(r.ok ? { text: 'Backup imported successfully.', kind: 'success' } : { text: `Failed: ${r.error}`, kind: 'error' });
              setTimeout(() => setMsg(null), 3000);
            }}
          />
        </label>
      </div>

      {msg && (
        <p class={msg.kind === 'success' ? 'muted' : 'error'} style="margin-top:10px;font-weight:500">
          {msg.text}
        </p>
      )}
    </div>
  );
}
