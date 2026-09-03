import type { Note } from '../../types/index.js';
import { NotesIcon, SearchIcon, TrashIcon } from './Icons.js';

interface Props {
  notes: Note[];
  searchQuery?: string | undefined;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onDelete?: ((id: string) => void) | undefined;
}

export function NotesList({ notes, searchQuery = '', selectedId, onSelect, onDelete }: Props) {
  if (notes.length === 0) {
    if (searchQuery.trim()) {
      return (
        <div class="empty-box" style="flex:1">
          <div class="empty-icon">
            <SearchIcon size={20} />
          </div>
          <strong style="color:var(--fg);font-size:12px">No matching notes</strong>
          <span class="muted">No notes found for "{searchQuery}"</span>
        </div>
      );
    }

    return (
      <div class="empty-box" style="flex:1">
        <div class="empty-icon">
          <NotesIcon size={20} />
        </div>
        <strong style="color:var(--fg);font-size:12px">No encrypted notes</strong>
        <span class="muted">Click <b>+ New note</b> to save secure notes, backup keys, or codes.</span>
      </div>
    );
  }

  return (
    <div class="notes-sidebar">
      {notes.map((n) => (
        <div
          key={n.id}
          class={`note-item${selectedId === n.id ? ' active' : ''}`}
          onClick={() => onSelect(n.id)}
        >
          <div style="display:flex;align-items:center;justify-content:space-between;gap:4px">
            <div class="note-title">{n.title || '(untitled)'}</div>
            {onDelete && (
              <button
                class="ghost"
                style="width:20px;height:20px;padding:0;opacity:0.6"
                title="Delete note"
                aria-label="Delete note"
                onClick={(e) => {
                  e.stopPropagation();
                  onDelete(n.id);
                }}
              >
                <TrashIcon size={12} />
              </button>
            )}
          </div>
          <div class="note-preview">{n.body ? n.body.slice(0, 36) : 'Empty note'}</div>
        </div>
      ))}
    </div>
  );
}
