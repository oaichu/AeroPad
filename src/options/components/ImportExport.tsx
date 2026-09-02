import { useState } from 'preact/hooks';
import { sendMessage } from '../../lib/send-message.js';

export function ImportExport() {
  const [msg, setMsg] = useState<{ text: string; kind: 'success' | 'error' } | null>(null);
  return (
    <section>
      <h2>Backup</h2>
      <p class="muted">Export your encrypted vault to a <code>.aeropad</code> file. Import replaces the current vault.</p>
      <div class="actions-row">
        <button
          onClick={async () => {
            const r = await sendMessage({ kind: 'exportAeropad' });
            if (r.ok && typeof r.data === 'string') {
              const blob = new Blob([r.data], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `aeropad-${new Date().toISOString().slice(0, 10)}.aeropad`;
              a.click();
              URL.revokeObjectURL(url);
              setMsg({ text: 'Exported.', kind: 'success' });
            } else {
              setMsg({ text: `Export failed: ${r.ok ? 'no data' : r.error}`, kind: 'error' });
            }
            setTimeout(() => setMsg(null), 2500);
          }}
        >Export .aeropad</button>
        <label class="secondary" style="display:inline-flex;align-items:center;padding:8px 12px;border:1px solid var(--border);border-radius:6px;cursor:pointer">
          Import…
          <input
            type="file"
            accept=".aeropad,application/json"
            style="display:none"
            onChange={async (e) => {
              const file = (e.target as HTMLInputElement).files?.[0];
              if (!file) return;
              const json = await file.text();
              const pw = prompt('Password for this backup (empty if none):') ?? '';
              const r = await sendMessage({ kind: 'importAeropad', json, password: pw, strategy: 'replace' });
              setMsg(r.ok ? { text: 'Imported.', kind: 'success' } : { text: `Failed: ${r.error}`, kind: 'error' });
              setTimeout(() => setMsg(null), 2500);
            }}
          />
        </label>
      </div>
      {msg && <p class={msg.kind === 'success' ? 'muted' : 'error'} style="margin-top:6px">{msg.text}</p>}
    </section>
  );
}
