import { useState } from 'preact/hooks';

interface Props {
  onAdd: (entry: {
    issuer: string;
    account: string;
    secret: string;
    algorithm: 'SHA1' | 'SHA256' | 'SHA512';
    digits: 6 | 8;
    period: number;
  }) => Promise<void> | void;
  onClose: () => void;
}

export function AddEntryDialog({ onAdd, onClose }: Props) {
  const [issuer, setIssuer] = useState('');
  const [account, setAccount] = useState('');
  const [secret, setSecret] = useState('');
  const [digits, setDigits] = useState<6 | 8>(6);
  const [period, setPeriod] = useState(30);
  return (
    <div style="position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center">
      <div style="background:var(--bg);color:var(--fg);padding:16px;border-radius:8px;width:300px">
        <h3>Add account</h3>
        <input
          placeholder="Issuer (e.g. GitHub)"
          value={issuer}
          onInput={(e) => setIssuer((e.target as HTMLInputElement).value)}
        />
        <input
          style="margin-top:6px"
          placeholder="Account"
          value={account}
          onInput={(e) => setAccount((e.target as HTMLInputElement).value)}
        />
        <input
          style="margin-top:6px"
          placeholder="Base32 secret"
          value={secret}
          onInput={(e) => setSecret((e.target as HTMLInputElement).value)}
        />
        <div style="margin-top:6px">
          <label>
            <input type="radio" name="d" checked={digits === 6} onChange={() => setDigits(6)} /> 6 digits
          </label>
          <label style="margin-left:8px">
            <input type="radio" name="d" checked={digits === 8} onChange={() => setDigits(8)} /> 8 digits
          </label>
        </div>
        <div style="margin-top:6px">
          Period:{' '}
          <input
            style="width:60px"
            type="number"
            value={period}
            onInput={(e) => setPeriod(Number((e.target as HTMLInputElement).value))}
          />{' '}
          s
        </div>
        <div style="margin-top:12px;display:flex;justify-content:flex-end;gap:8px">
          <button onClick={onClose}>Cancel</button>
          <button
            onClick={async () => {
              await onAdd({ issuer, account, secret, algorithm: 'SHA1', digits, period });
              onClose();
            }}
          >
            Add
          </button>
        </div>
      </div>
    </div>
  );
}