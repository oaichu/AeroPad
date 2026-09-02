import { useEffect, useState } from 'preact/hooks';
import type { CodeEntry } from '../../types/index.js';
import { currentCode, remainingSeconds } from '../../lib/totp.js';

interface Props { entry: CodeEntry; onCopy?: (code: string) => void; }

export function CodeItem({ entry, onCopy }: Props) {
  const [code, setCode] = useState('······');
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

  return (
    <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--muted)">
      <div><strong>{entry.issuer}</strong> <span class="muted">{entry.account}</span></div>
      <div style="text-align:right">
        <div style="font-family:monospace;font-size:18px" onClick={() => onCopy?.(code)}>{code}</div>
        <div class="muted" style="font-size:11px">{remain}s</div>
      </div>
    </div>
  );
}