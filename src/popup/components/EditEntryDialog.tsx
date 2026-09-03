import { useState } from 'preact/hooks';
import type { CodeEntry } from '../../types/index.js';
import type { Response } from '../../lib/messages.js';
import { CloseIcon } from './Icons.js';

interface Props {
  entry: CodeEntry;
  onSave: (id: string, patch: Partial<CodeEntry>) => Promise<Response>;
  onClose: () => void;
}

export function EditEntryDialog({ entry, onSave, onClose }: Props) {
  const [issuer, setIssuer] = useState(entry.issuer);
  const [account, setAccount] = useState(entry.account);
  const [digits, setDigits] = useState<6 | 8>(entry.digits);
  const [period, setPeriod] = useState(entry.period);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const canSubmit = issuer.trim().length > 0;

  return (
    <div class="modal-overlay" onClick={onClose}>
      <div class="modal-content" onClick={(e) => e.stopPropagation()}>
        <div class="modal-header">
          <h3>Edit account</h3>
          <button class="ghost icon-btn" onClick={onClose} aria-label="Close">
            <CloseIcon size={16} />
          </button>
        </div>

        <label>Issuer</label>
        <input
          autoFocus
          value={issuer}
          onInput={(e) => setIssuer((e.target as HTMLInputElement).value)}
          placeholder="GitHub"
        />

        <label>Account (username / email)</label>
        <input
          value={account}
          onInput={(e) => setAccount((e.target as HTMLInputElement).value)}
          placeholder="me@example.com"
        />

        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:10px">
          <div style="display:flex;align-items:center;gap:12px">
            <label style="display:flex;align-items:center;gap:5px;margin:0;cursor:pointer">
              <input type="radio" name="edit_d" checked={digits === 6} onChange={() => setDigits(6)} style="width:auto;margin:0" />
              6 digits
            </label>
            <label style="display:flex;align-items:center;gap:5px;margin:0;cursor:pointer">
              <input type="radio" name="edit_d" checked={digits === 8} onChange={() => setDigits(8)} style="width:auto;margin:0" />
              8 digits
            </label>
          </div>
          <div style="display:flex;align-items:center;gap:4px">
            <span class="muted" style="font-size:11px">Period</span>
            <input
              type="number"
              min={15}
              max={120}
              step={5}
              value={period}
              onInput={(e) => setPeriod(Number((e.target as HTMLInputElement).value) || 30)}
              style="width:54px;padding:4px 6px;text-align:center"
            />
            <span class="muted" style="font-size:11px">s</span>
          </div>
        </div>

        {err && <p class="error">{err}</p>}

        <div class="modal-footer">
          <button class="secondary" onClick={onClose}>Cancel</button>
          <button
            disabled={!canSubmit || busy}
            onClick={async () => {
              setBusy(true); setErr(null);
              const r = await onSave(entry.id, { issuer, account, digits, period });
              setBusy(false);
              if (!r.ok) setErr(r.error);
              else onClose();
            }}
          >
            {busy ? 'Saving…' : 'Save changes'}
          </button>
        </div>
      </div>
    </div>
  );
}
