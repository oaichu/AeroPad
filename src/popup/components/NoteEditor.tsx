import { useEffect, useState } from 'preact/hooks';
import type { Note } from '../../types/index.js';

interface Props { note: Note; onChange: (n: Note) => void; }

export function NoteEditor({ note, onChange }: Props) {
  const [draft, setDraft] = useState(note);
  useEffect(() => setDraft(note), [note.id]);
  useEffect(() => {
    const id = setTimeout(() => {
      if (draft !== note) onChange({ ...draft, updatedAt: Date.now() });
    }, 500);
    return () => clearTimeout(id);
  }, [draft.body, draft.title]);
  return (
    <div>
      <input
        value={draft.title}
        placeholder="Title"
        onInput={(e) => setDraft({ ...draft, title: (e.target as HTMLInputElement).value })}
      />
      <textarea
        style="width:100%;min-height:120px;margin-top:8px"
        value={draft.body}
        onInput={(e) => setDraft({ ...draft, body: (e.target as HTMLTextAreaElement).value })}
      />
    </div>
  );
}