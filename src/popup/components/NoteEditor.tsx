import { useEffect, useState } from 'preact/hooks';
import type { Note } from '../../types/index.js';
import { TrashIcon, CheckIcon } from './Icons.js';

interface Props {
  note: Note;
  onChange: (n: Note) => void;
  onDelete?: ((id: string) => void) | undefined;
}

export function NoteEditor({ note, onChange, onDelete }: Props) {
  const [draft, setDraft] = useState(note);
  const [isSaved, setIsSaved] = useState(true);

  useEffect(() => {
    setDraft(note);
    setIsSaved(true);
  }, [note.id]);

  useEffect(() => {
    if (draft.body === note.body && draft.title === note.title) return;
    setIsSaved(false);
    const id = setTimeout(() => {
      onChange({ ...draft, updatedAt: Date.now() });
      setIsSaved(true);
    }, 450);
    return () => clearTimeout(id);
  }, [draft.body, draft.title]);

  const charCount = draft.body.length;

  return (
    <div class="note-main">
      <div class="note-main-header">
        <input
          value={draft.title}
          placeholder="Note title…"
          onInput={(e) => setDraft({ ...draft, title: (e.target as HTMLInputElement).value })}
          style="font-weight:600;font-size:13px;flex:1"
        />
        <div style="display:flex;align-items:center;gap:6px">
          <span class="muted" style="font-size:10px;display:flex;align-items:center;gap:3px">
            {isSaved ? <><CheckIcon size={10} style="color:var(--success)" /> Saved</> : 'Saving…'}
          </span>
          {onDelete && (
            <button
              class="ghost"
              style="width:26px;height:26px;padding:0;color:var(--danger)"
              title="Delete this note"
              aria-label="Delete this note"
              onClick={() => onDelete(note.id)}
            >
              <TrashIcon size={14} />
            </button>
          )}
        </div>
      </div>

      <textarea
        value={draft.body}
        placeholder="Write your encrypted notes here. Supports recovery codes, private keys, or credentials…"
        onInput={(e) => setDraft({ ...draft, body: (e.target as HTMLTextAreaElement).value })}
      />

      <div style="display:flex;justify-content:flex-end">
        <span class="muted" style="font-size:10px">{charCount} chars</span>
      </div>
    </div>
  );
}
