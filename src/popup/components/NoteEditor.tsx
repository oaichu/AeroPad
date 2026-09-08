import { useEffect, useRef, useState } from 'preact/hooks';
import type { Note } from '../../types/index.js';
import { TrashIcon, CheckIcon } from './Icons.js';

interface Props {
  note: Note;
  onChange: (n: Note) => void | Promise<void>;
  onDelete?: ((id: string) => void) | undefined;
}

export function NoteEditor({ note, onChange, onDelete }: Props) {
  const [draft, setDraft] = useState(note);
  const [isSaved, setIsSaved] = useState(true);

  const draftRef = useRef(draft);
  draftRef.current = draft;

  const dirtyRef = useRef(false);
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const flushSave = () => {
    if (saveTimerRef.current) {
      clearTimeout(saveTimerRef.current);
      saveTimerRef.current = null;
    }
    if (dirtyRef.current) {
      dirtyRef.current = false;
      setIsSaved(true);
      void onChange({ ...draftRef.current, updatedAt: Date.now() });
    }
  };

  // Sync draft when switching to a different note
  useEffect(() => {
    if (dirtyRef.current) {
      void onChange({ ...draftRef.current, updatedAt: Date.now() });
      dirtyRef.current = false;
    }
    setDraft(note);
    setIsSaved(true);
  }, [note.id]);

  // Flush on unmount (e.g. popup closing, switching tab)
  useEffect(() => {
    const handleBeforeUnload = () => {
      if (dirtyRef.current) {
        void onChange({ ...draftRef.current, updatedAt: Date.now() });
        dirtyRef.current = false;
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    window.addEventListener('pagehide', handleBeforeUnload);

    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
      window.removeEventListener('pagehide', handleBeforeUnload);
      if (dirtyRef.current) {
        void onChange({ ...draftRef.current, updatedAt: Date.now() });
        dirtyRef.current = false;
      }
      if (saveTimerRef.current) {
        clearTimeout(saveTimerRef.current);
        saveTimerRef.current = null;
      }
    };
  }, []);

  const handleInput = (fields: Partial<Note>) => {
    const next = { ...draft, ...fields };
    setDraft(next);
    draftRef.current = next;
    dirtyRef.current = true;
    setIsSaved(false);

    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(() => {
      flushSave();
    }, 400);
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
      e.preventDefault();
      flushSave();
    }
  };

  const charCount = draft.body.length;

  return (
    <div class="note-main" onKeyDown={handleKeyDown}>
      <div class="note-main-header">
        <input
          value={draft.title}
          placeholder="Note title…"
          onInput={(e) => handleInput({ title: (e.target as HTMLInputElement).value })}
          onBlur={flushSave}
          style="font-weight:600;font-size:13px;flex:1"
        />
        <div style="display:flex;align-items:center;gap:6px">
          <button
            type="button"
            class="ghost"
            style={`font-size:10px;padding:2px 6px;height:24px;border-radius:var(--radius-sm);display:flex;align-items:center;gap:3px;${
              !isSaved ? 'color:var(--accent);font-weight:600' : 'color:var(--muted)'
            }`}
            onClick={flushSave}
            title={isSaved ? 'Note saved' : 'Click to save now (Ctrl+S)'}
          >
            {isSaved ? (
              <><CheckIcon size={10} style="color:var(--success)" /> Saved</>
            ) : (
              'Save'
            )}
          </button>
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
        onInput={(e) => handleInput({ body: (e.target as HTMLTextAreaElement).value })}
        onBlur={flushSave}
      />

      <div style="display:flex;justify-content:flex-end">
        <span class="muted" style="font-size:10px">{charCount} chars</span>
      </div>
    </div>
  );
}
