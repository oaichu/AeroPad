import type { CodeEntry } from '../../types/index.js';
import { CodeItem } from './CodeItem.js';

interface Props { entries: CodeEntry[]; }

export function CodeList({ entries }: Props) {
  if (entries.length === 0) {
    return (
      <div class="empty">
        <div class="ico">🔐</div>
        <strong>No accounts yet</strong>
        <span>Click <b>+ Add</b> to add your first TOTP account.</span>
      </div>
    );
  }
  return (
    <div>
      {entries.map((e) => (
        <CodeItem
          key={e.id}
          entry={e}
          onCopy={(c) => navigator.clipboard.writeText(c).catch(() => { /* clipboard may be denied */ })}
        />
      ))}
    </div>
  );
}
