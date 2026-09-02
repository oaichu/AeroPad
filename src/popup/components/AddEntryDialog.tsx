import { useState } from 'preact/hooks';
import type { Response } from '../../lib/messages.js';

type Entry = { issuer: string; account: string; secret: string; algorithm: 'SHA1' | 'SHA256' | 'SHA512'; digits: 6 | 8; period: number; };

interface Props {
  onAdd: (entry: Entry) => Promise<Response>;
  onClose: () => void;
}

export function AddEntryDialog({ onAdd, onClose }: Props) {
  const [issuer, setIssuer] = useState('');
  const [account, setAccount] = useState('');
  const [secret, setSecret] = useState('');
  const [digits, setDigits] = useState<6 | 8>(6);
  const [period, setPeriod] = useState(30);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const canSubmit = issuer.trim().length > 0 && /^[A-Z2-7]+=*$/.test(secret.replace(/\s/g, '').toUpperCase());

  return (
    <div style="position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:10;padding:12px">
      <div style="background:var(--bg);color:var(--fg);padding:16px;border-radius:8px;width:320px;max-width:100%;box-shadow:0 4px 12px rgba(0,0,0,0.15)">
        <h3 style="margin-top:0">Add account</h3>
        <label>Issuer (e.g. GitHub)</label>
        <input
          autoFocus
          value={issuer}
          onInput={(e) => setIssuer((e.target as HTMLInputElement).value)}
          placeholder="GitHub"
        />
        <label>Account (optional)</label>
        <input
          value={account}
          onInput={(e) => setAccount((e.target as HTMLInputElement).value)}
          placeholder="me@example.com"
        />
        <label>Base32 secret</label>
        <input
          value={secret}
          onInput={(e) => setSecret((e.target as HTMLInputElement).value.toUpperCase())}
          placeholder="JBSWY3DPEHPK3PXP"
        />
        <div class="row" style="margin-top:8px">
          <label style="display:flex;align-items:center;gap:4px;margin:0">
            <input type="radio" name="d" checked={digits === 6} onChange={() => setDigits(6)} style="width:auto" />6 digits
          </label>
          <label style="display:flex;align-items:center;gap:4px;margin:0">
            <input type="radio" name="d" checked={digits === 8} onChange={() => setDigits(8)} style="width:auto" />8 digits
          </label>
          <span class="muted" style="margin-left:auto">Period</span>
          <input
            type="number"
            min={15} max={120} step={5}
            value={period}
            onInput={(e) => setPeriod(Number((e.target as HTMLInputElement).value) || 30)}
            style="width:64px"
          />
          <span class="muted">s</span>
        </div>
        {err && <p class="error">{err}</p>}
        <div class="actions-row" style="justify-content:flex-end">
          <button class="secondary" onClick={onClose}>Cancel</button>
          <button
            disabled={!canSubmit || busy}
            onClick={async () => {
              setBusy(true); setErr(null);
              const r = await onAdd({ issuer, account, secret: secret.replace(/\s/g, '').toUpperCase(), algorithm: 'SHA1', digits, period });
              setBusy(false);
              if (!r.ok) setErr(r.error);
              else onClose();
            }}
          >
            Add
          </button>
        </div>
      </div>
    </div>
  );
}
