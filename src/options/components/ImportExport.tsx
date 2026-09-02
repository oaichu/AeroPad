import { useState } from 'preact/hooks';
import { sendMessage } from '../../lib/send-message.js';

export function ImportExport() {
  const [msg, setMsg] = useState('');
  return (
    <section>
      <h2>Backup</h2>
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
            setMsg('Exported.');
          } else if (!r.ok) {
            setMsg(`Failed: ${r.error}`);
          }
        }}
      >
        Export .aeropad
      </button>
      <input
        style="margin-left:8px"
        type="file"
        accept=".aeropad,application/json"
        onChange={async (e) => {
          const file = (e.target as HTMLInputElement).files?.[0];
          if (!file) return;
          const json = await file.text();
          const pw = window.prompt('Password for this backup (empty if none):') ?? '';
          const r = await sendMessage({ kind: 'importAeropad', json, password: pw, strategy: 'replace' });
          setMsg(r.ok ? 'Imported.' : `Failed: ${r.error}`);
        }}
      />
      {msg && <p>{msg}</p>}
    </section>
  );
}