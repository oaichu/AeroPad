import { useEffect, useState } from 'preact/hooks';
import type { Note } from '../../types/index.js';

interface Props { note: Note; onChange: (n: Note) => void; }

export function NoteEditor({ note, onChange }: Props) {
  const [draft, setDraft] = useState(note);
  useEffect(() => setDraft(note), [note.id]);
  useEffect(() => {
    const id = setTimeout(() => { if (draft !== note) onChange({ ...draft, updatedAt: Date.now() }); }, 500);
    return () => clearTimeout(id);
  }, [draft.body, draft.title]);
  return (
    <div class="notes-editor">
      <input
        value={draft.title}
        placeholder="Title"
        onInput={(e) => setDraft({ ...draft, title: (e.target as HTMLInputElement).value })}
      />
      <textarea
        value={draft.body}
        placeholder="Write your note here. Markdown supported."
        onInput={(e) => setDraft({ ...draft, body: (e.target as HTMLTextAreaElement).value })}
      />
    </div>
  );
}
