import type { Note } from '../../types/index.js';

interface Props { notes: Note[]; onSelect: (id: string) => void; selectedId: string | null; }

export function NotesList({ notes, onSelect, selectedId }: Props) {
  if (notes.length === 0) return <p class="muted">No notes yet.</p>;
  return (
    <ul style="list-style:none;padding:0;margin:0">
      {notes.map((n) => (
        <li
          key={n.id}
          onClick={() => onSelect(n.id)}
          style={`padding:6px 8px;cursor:pointer;${selectedId === n.id ? 'background:var(--accent);color:white' : ''}`}
        >
          {n.title || '(untitled)'}
        </li>
      ))}
    </ul>
  );
}