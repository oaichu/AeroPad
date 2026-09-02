import type { Note } from '../../types/index.js';

interface Props { notes: Note[]; onSelect: (id: string) => void; selectedId: string | null; }

export function NotesList({ notes, onSelect, selectedId }: Props) {
  if (notes.length === 0) {
    return (
      <div class="empty">
        <div class="ico">📝</div>
        <strong>No notes yet</strong>
        <span>Click <b>+ New</b> to add one.</span>
      </div>
    );
  }
  return (
    <div class="notes-list">
      {notes.map((n) => (
        <div
          key={n.id}
          class={`notes-list-item${selectedId === n.id ? ' active' : ''}`}
          onClick={() => onSelect(n.id)}
        >
          {n.title || '(untitled)'}
        </div>
      ))}
    </div>
  );
}
