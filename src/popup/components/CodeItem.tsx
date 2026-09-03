import { useEffect, useState } from 'preact/hooks';
import type { CodeEntry } from '../../types/index.js';
import { currentCode, remainingSeconds } from '../../lib/totp.js';
import { CopyIcon, CheckIcon, EditIcon, TrashIcon } from './Icons.js';

interface Props {
  entry: CodeEntry;
  onCopy?: ((code: string) => void) | undefined;
  onEdit?: ((entry: CodeEntry) => void) | undefined;
  onDelete?: ((id: string) => void) | undefined;
}

function getBrandColor(issuer: string): { bg: string; color: string; label: string } {
  const norm = issuer.trim().toLowerCase();
  if (norm.includes('github')) return { bg: '#24292e', color: '#ffffff', label: 'GH' };
  if (norm.includes('google')) return { bg: '#ea4335', color: '#ffffff', label: 'G' };
  if (norm.includes('aws') || norm.includes('amazon')) return { bg: '#ff9900', color: '#111827', label: 'AWS' };
  if (norm.includes('discord')) return { bg: '#5865f2', color: '#ffffff', label: 'DC' };
  if (norm.includes('microsoft')) return { bg: '#00a4ef', color: '#ffffff', label: 'MS' };
  if (norm.includes('slack')) return { bg: '#4a154b', color: '#ffffff', label: 'SL' };
  if (norm.includes('apple')) return { bg: '#333333', color: '#ffffff', label: 'AP' };
  if (norm.includes('gitlab')) return { bg: '#fc6d26', color: '#ffffff', label: 'GL' };
  if (norm.includes('binance')) return { bg: '#f3ba2f', color: '#111827', label: 'BN' };

  // Fallback: initial 1-2 chars with hash-based color
  const hash = issuer.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
  const hues = [200, 220, 260, 280, 160, 30, 340];
  const hue = hues[hash % hues.length];
  const label = (issuer.slice(0, 2) || '2F').toUpperCase();
  return { bg: `hsl(${hue}, 60%, 25%)`, color: `hsl(${hue}, 85%, 85%)`, label };
}

function formatCode(raw: string): string {
  if (raw.length === 6) {
    return `${raw.slice(0, 3)} ${raw.slice(3)}`;
  }
  if (raw.length === 8) {
    return `${raw.slice(0, 4)} ${raw.slice(4)}`;
  }
  return raw;
}

export function CodeItem({ entry, onCopy, onEdit, onDelete }: Props) {
  const [code, setCode] = useState('••••••');
  const [remain, setRemain] = useState(entry.period);
  const [copied, setCopied] = useState(false);

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

  const handleCopy = (e?: Event) => {
    e?.stopPropagation();
    navigator.clipboard.writeText(code).catch(() => {});
    onCopy?.(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  const brand = getBrandColor(entry.issuer || '');
  const isExpiring = remain <= 5;
  const isWarning = remain <= 10 && remain > 5;
  const timerColor = isExpiring ? 'var(--danger)' : isWarning ? 'var(--warning)' : 'var(--success)';

  const radius = 10;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (remain / entry.period) * circumference;

  return (
    <div class="code-card">
      <div class="code-card-header">
        <div class="account-info">
          <div class="service-avatar" style={`background:${brand.bg};color:${brand.color}`}>
            {brand.label}
          </div>
          <div class="account-titles">
            <div class="issuer-name" title={entry.issuer}>{entry.issuer || '(unnamed)'}</div>
            <div class="account-id" title={entry.account}>{entry.account || 'No username'}</div>
          </div>
        </div>
        <div class="card-actions">
          {onEdit && (
            <button
              class="ghost"
              title="Edit account"
              aria-label="Edit account"
              onClick={(e) => { e.stopPropagation(); onEdit(entry); }}
            >
              <EditIcon size={14} />
            </button>
          )}
          {onDelete && (
            <button
              class="ghost delete-btn"
              title="Delete account"
              aria-label="Delete account"
              onClick={(e) => { e.stopPropagation(); onDelete(entry.id); }}
            >
              <TrashIcon size={14} />
            </button>
          )}
        </div>
      </div>

      <div class="code-card-body" onClick={handleCopy} title="Click to copy code">
        <div class={`code-digits${isExpiring ? ' danger-state' : ''}`}>
          {formatCode(code)}
        </div>

        <div class="timer-container">
          {copied ? (
            <div class="copy-feedback-badge">
              <CheckIcon size={12} />
              <span>Copied</span>
            </div>
          ) : (
            <div class="svg-ring-wrap" title={`${remain}s remaining`}>
              <svg width="28" height="28" viewBox="0 0 28 28">
                <circle class="bg" cx="14" cy="14" r={radius} stroke-width="2.5" />
                <circle
                  class="progress"
                  cx="14"
                  cy="14"
                  r={radius}
                  stroke-width="2.5"
                  stroke={timerColor}
                  stroke-dasharray={circumference}
                  stroke-dashoffset={strokeDashoffset}
                />
              </svg>
              <span class="secs-label" style={`color:${timerColor}`}>{remain}</span>
            </div>
          )}

          <button
            class="ghost"
            style="width:28px;height:28px;padding:0"
            onClick={handleCopy}
            title="Copy code"
            aria-label="Copy code"
          >
            {copied ? <CheckIcon size={15} style="color:var(--success)" /> : <CopyIcon size={15} />}
          </button>
        </div>
      </div>
    </div>
  );
}
