import type { CodeEntry } from '../../types/index.js';
import { CodeItem } from './CodeItem.js';
import { ShieldIcon, SearchIcon } from './Icons.js';

interface Props {
  entries: CodeEntry[];
  searchQuery?: string | undefined;
  onEdit?: ((entry: CodeEntry) => void) | undefined;
  onDelete?: ((id: string) => void) | undefined;
  onCopy?: ((code: string) => void) | undefined;
}

export function CodeList({ entries, searchQuery = '', onEdit, onDelete, onCopy }: Props) {
  if (entries.length === 0) {
    if (searchQuery.trim()) {
      return (
        <div class="empty-box">
          <div class="empty-icon">
            <SearchIcon size={20} />
          </div>
          <strong style="color:var(--fg)">No matching accounts</strong>
          <span class="muted">No accounts matched "{searchQuery}"</span>
        </div>
      );
    }

    return (
      <div class="empty-box">
        <div class="empty-icon">
          <ShieldIcon size={22} />
        </div>
        <strong style="color:var(--fg)">No accounts yet</strong>
        <span class="muted">Click <b>+ Add account</b> to protect your logins with 2FA.</span>
      </div>
    );
  }

  return (
    <div class="code-list-container">
      {entries.map((e) => (
        <CodeItem
          key={e.id}
          entry={e}
          onCopy={onCopy}
          onEdit={onEdit}
          onDelete={onDelete}
        />
      ))}
    </div>
  );
}
