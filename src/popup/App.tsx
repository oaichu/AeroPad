import { useEffect, useState } from 'preact/hooks';
import { UnlockDialog } from './components/UnlockDialog.js';
import { CodeList } from './components/CodeList.js';
import { NotesList } from './components/NotesList.js';
import { NoteEditor } from './components/NoteEditor.js';
import { AddEntryDialog } from './components/AddEntryDialog.js';
import { SettingsMenu } from './components/SettingsMenu.js';
import { sendMessage } from '../lib/send-message.js';
import type { CodeEntry, Note } from '../types/index.js';

export function App() {
  const [unlocked, setUnlocked] = useState<boolean | null>(null);
  const [tab, setTab] = useState<'codes' | 'notes'>('codes');
  const [codes, setCodes] = useState<CodeEntry[]>([]);
  const [notes, setNotes] = useState<Note[]>([]);
  const [selectedNote, setSelectedNote] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);

  const refresh = async () => {
    const [c, n] = await Promise.all([
      sendMessage({ kind: 'getCodes' }),
      sendMessage({ kind: 'getNotes' }),
    ]);
    if (c.ok) setCodes((c.data ?? []) as CodeEntry[]);
    if (n.ok) setNotes((n.data ?? []) as Note[]);
  };

  useEffect(() => {
    sendMessage({ kind: 'isUnlocked' }).then((r) => {
      if (r.ok) {
        setUnlocked(r.data === true);
        if (r.data === true) void refresh();
      }
    });
  }, []);

  if (unlocked === null) return <p class="muted">loading…</p>;
  if (!unlocked) {
    return (
      <UnlockDialog
        onSubmit={async (pw) => {
          const r = await sendMessage({ kind: 'unlock', password: pw });
          if (r.ok) {
            setUnlocked(true);
            void refresh();
          }
          return r;
        }}
      />
    );
  }

  const currentNote = selectedNote ? notes.find((n) => n.id === selectedNote) ?? null : null;

  return (
    <div>
      <div style="display:flex;gap:8px;margin-bottom:12px">
        <button onClick={() => setTab('codes')}>Codes</button>
        <button onClick={() => setTab('notes')}>Notes</button>
      </div>
      {tab === 'codes' ? (
        <>
          <CodeList entries={codes} />
          <button style="margin-top:8px" onClick={() => setShowAdd(true)}>+ Add</button>
          {showAdd && (
            <AddEntryDialog
              onClose={() => setShowAdd(false)}
              onAdd={async (e) => {
                await sendMessage({ kind: 'addEntry', entry: e });
                await refresh();
              }}
            />
          )}
        </>
      ) : (
        <div style="display:flex;gap:12px">
          <div style="flex:1">
            <NotesList notes={notes} selectedId={selectedNote} onSelect={setSelectedNote} />
          </div>
          <div style="flex:2">
            {currentNote && (
              <NoteEditor
                note={currentNote}
                onChange={async (n) => {
                  await sendMessage({ kind: 'saveNote', note: n });
                  await refresh();
                }}
              />
            )}
          </div>
        </div>
      )}
      <SettingsMenu
        onLock={async () => {
          await sendMessage({ kind: 'lock' });
          setUnlocked(false);
        }}
        onOpenOptions={() => { chrome.runtime.openOptionsPage(); }}
      />
    </div>
  );
}