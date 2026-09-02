import { useEffect, useState } from 'preact/hooks';
import type { CodeEntry } from '../../types/index.js';
import { currentCode, remainingSeconds } from '../../lib/totp.js';

interface Props { entry: CodeEntry; onCopy?: (code: string) => void; }

export function CodeItem({ entry, onCopy }: Props) {
  const [code, setCode] = useState('••••••');
  const [remain, setRemain] = useState(entry.period);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      if (cancelled) return;
      setCode(await currentCode(entry));
      setRemain(remainingSeconds(entry));
    };
    void tick();
    const id = setInterval(tick, 1000);
    return () => { cancelled = true; clearInterval(id); };
  }, [entry]);

  const pct = remain / entry.period;
  const expired = remain <= 1;

  return (
    <div
      class={`code-row${expired ? ' expired' : ''}`}
      onClick={() => onCopy?.(code)}
      title="Click to copy"
    >
      <div class="who">
        <strong>{entry.issuer || '(unnamed)'}</strong>
        {entry.account && <span class="acct">{entry.account}</span>}
      </div>
      <div class="ring" style={`--pct:${pct}`}>
        <span class="secs">{remain}</span>
      </div>
      <div class="code">{code}</div>
    </div>
  );
}
