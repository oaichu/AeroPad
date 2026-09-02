import type { CodeEntry } from '../../types/index.js';
import { CodeItem } from './CodeItem.js';

interface Props { entries: CodeEntry[]; }

export function CodeList({ entries }: Props) {
  if (entries.length === 0) return <p class="muted">No accounts yet.</p>;
  return (
    <div>
      {entries.map((e) => (
        <CodeItem
          key={e.id}
          entry={e}
          onCopy={(c) => { void navigator.clipboard.writeText(c); }}
        />
      ))}
    </div>
  );
}