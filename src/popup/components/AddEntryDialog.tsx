import { useState } from 'preact/hooks';
import type { Response } from '../../lib/messages.js';
import { parseOtpauthUri } from '../../lib/totp.js';
import { CloseIcon, KeyIcon } from './Icons.js';

type Entry = {
  issuer: string;
  account: string;
  secret: string;
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  digits: 6 | 8;
  period: number;
};

interface Props {
  onAdd: (entry: Entry) => Promise<Response>;
  onClose: () => void;
}

export function AddEntryDialog({ onAdd, onClose }: Props) {
  const [uriInput, setUriInput] = useState('');
  const [issuer, setIssuer] = useState('');
  const [account, setAccount] = useState('');
  const [secret, setSecret] = useState('');
  const [digits, setDigits] = useState<6 | 8>(6);
  const [period, setPeriod] = useState(30);
  const [algo, setAlgo] = useState<'SHA1' | 'SHA256' | 'SHA512'>('SHA1');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const cleanSecret = secret.replace(/\s/g, '').toUpperCase();
  const isValidSecret = /^[A-Z2-7]+=*$/.test(cleanSecret);
  const canSubmit = issuer.trim().length > 0 && isValidSecret;

  const handleUriChange = (val: string) => {
    setUriInput(val);
    const parsed = parseOtpauthUri(val);
    if (parsed) {
      setIssuer(parsed.issuer);
      setAccount(parsed.account);
      setSecret(parsed.secret);
      setDigits(parsed.digits);
      setPeriod(parsed.period);
      setAlgo(parsed.algorithm);
      setErr(null);
    }
  };

  return (
    <div class="modal-overlay" onClick={onClose}>
      <div class="modal-content" onClick={(e) => e.stopPropagation()}>
        <div class="modal-header">
          <h3 style="display:flex;align-items:center;gap:6px">
            <KeyIcon size={16} />
            Add 2FA Account
          </h3>
          <button class="ghost icon-btn" onClick={onClose} aria-label="Close">
            <CloseIcon size={16} />
          </button>
        </div>

        <label>
          Paste otpauth:// URL (Optional)
        </label>
        <input
          value={uriInput}
          onInput={(e) => handleUriChange((e.target as HTMLInputElement).value)}
          placeholder="otpauth://totp/Service:user?secret=..."
          style="font-size:11px"
        />

        <label>Issuer *</label>
        <input
          autoFocus={!uriInput}
          value={issuer}
          onInput={(e) => setIssuer((e.target as HTMLInputElement).value)}
          placeholder="GitHub, Google, AWS..."
        />

        <label>Account username or email</label>
        <input
          value={account}
          onInput={(e) => setAccount((e.target as HTMLInputElement).value)}
          placeholder="me@example.com"
        />

        <label>
          Base32 Secret Key *
          {secret.length > 0 && !isValidSecret && (
            <span class="error" style="font-size:10px">Invalid Base32</span>
          )}
        </label>
        <input
          value={secret}
          onInput={(e) => {
            const v = (e.target as HTMLInputElement).value;
            if (v.trim().startsWith('otpauth://')) {
              handleUriChange(v);
            } else {
              setSecret(v.toUpperCase());
            }
          }}
          placeholder="JBSWY3DPEHPK3PXP"
          style="font-family:var(--font-mono);font-size:12px;letter-spacing:0.04em"
        />

        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:10px">
          <div style="display:flex;align-items:center;gap:12px">
            <label style="display:flex;align-items:center;gap:5px;margin:0;cursor:pointer">
              <input type="radio" name="d" checked={digits === 6} onChange={() => setDigits(6)} style="width:auto;margin:0" />
              6 digits
            </label>
            <label style="display:flex;align-items:center;gap:5px;margin:0;cursor:pointer">
              <input type="radio" name="d" checked={digits === 8} onChange={() => setDigits(8)} style="width:auto;margin:0" />
              8 digits
            </label>
          </div>
          <div style="display:flex;align-items:center;gap:4px">
            <span class="muted" style="font-size:11px">Period</span>
            <input
              type="number"
              min={15} max={120} step={5}
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
              const r = await onAdd({
                issuer: issuer.trim(),
                account: account.trim(),
                secret: cleanSecret,
                algorithm: algo,
                digits,
                period,
              });
              setBusy(false);
              if (!r.ok) setErr(r.error);
              else onClose();
            }}
          >
            {busy ? 'Adding…' : 'Add account'}
          </button>
        </div>
      </div>
    </div>
  );
}
