import { useEffect, useState } from 'preact/hooks';
import { UnlockDialog } from './components/UnlockDialog.js';
import { CreateVaultDialog } from './components/CreateVaultDialog.js';
import { CodeList } from './components/CodeList.js';
import { NotesList } from './components/NotesList.js';
import { NoteEditor } from './components/NoteEditor.js';
import { AddEntryDialog } from './components/AddEntryDialog.js';
import { sendMessage } from '../lib/send-message.js';
import type { CodeEntry, Note } from '../types/index.js';

type Status = 'no-vault' | 'locked' | 'unlocked';

export function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [tab, setTab] = useState<'codes' | 'notes'>('codes');
  const [codes, setCodes] = useState<CodeEntry[]>([]);
  const [notes, setNotes] = useState<Note[]>([]);
  const [selectedNote, setSelectedNote] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  const refresh = async () => {
    const [c, n] = await Promise.all([
      sendMessage({ kind: 'getCodes' }),
      sendMessage({ kind: 'getNotes' }),
    ]);
    if (c.ok) setCodes((c.data ?? []) as CodeEntry[]);
    if (n.ok) setNotes((n.data ?? []) as Note[]);
  };

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 1500);
  };

  useEffect(() => {
    sendMessage({ kind: 'isUnlocked' }).then((r) => {
      if (r.ok && (r.data === 'no-vault' || r.data === 'locked' || r.data === 'unlocked')) {
        setStatus(r.data);
        if (r.data === 'unlocked') void refresh();
      }
    });
  }, []);

  if (status === null) return <p class="muted" style="text-align:center;padding:40px 0">loading…</p>;
  if (status === 'no-vault') {
    return (
      <CreateVaultDialog
        onSubmit={async (pw) => {
          const r = await sendMessage({ kind: 'createVault', password: pw });
          if (r.ok) { setStatus('unlocked'); void refresh(); }
          return r;
        }}
      />
    );
  }
  if (status === 'locked') {
    return (
      <UnlockDialog
        onSubmit={async (pw) => {
          const r = await sendMessage({ kind: 'unlock', password: pw });
          if (r.ok) { setStatus('unlocked'); void refresh(); }
          return r;
        }}
      />
    );
  }

  const currentNote = selectedNote ? notes.find((n) => n.id === selectedNote) ?? null : null;
  const addLabel = tab === 'codes' ? '+ Add account' : '+ New note';

  return (
    <div>
      <div class="header">
        <h1>🔐 AeroPad</h1>
        <div style="display:flex;gap:4px">
          <button
            class="ghost"
            onClick={async () => {
              await sendMessage({ kind: 'lock' });
              setStatus('locked');
            }}
            title="Lock now"
            aria-label="Lock now"
          >🔒</button>
          <button class="ghost" onClick={() => chrome.runtime.openOptionsPage()} title="Settings" aria-label="Settings">⚙</button>
        </div>
      </div>

      <div class="tabs" role="tablist">
        <button
          role="tab"
          aria-selected={tab === 'codes'}
          class={tab === 'codes' ? 'active' : ''}
          onClick={() => setTab('codes')}
        >Codes <span class="muted">({codes.length})</span></button>
        <button
          role="tab"
          aria-selected={tab === 'notes'}
          class={tab === 'notes' ? 'active' : ''}
          onClick={() => setTab('notes')}
        >Notes <span class="muted">({notes.length})</span></button>
      </div>

      {tab === 'codes' ? (
        <CodeList entries={codes} />
      ) : (
        <div class="notes-wrap">
          <NotesList notes={notes} selectedId={selectedNote} onSelect={setSelectedNote} />
          {currentNote ? (
            <div class="notes-editor">
              <NoteEditor note={currentNote} onChange={async (n) => {
                await sendMessage({ kind: 'saveNote', note: n });
                await refresh();
              }} />
            </div>
          ) : (
            <div class="empty" style="flex:1">
              <div class="ico">📝</div>
              <span>{notes.length === 0 ? 'No notes yet' : 'Select a note'}</span>
            </div>
          )}
        </div>
      )}

      <div class="actions">
        <button
          class="grow"
          onClick={() => {
            if (tab === 'codes') { setShowAdd(true); return; }
            const id = crypto.randomUUID();
            void sendMessage({ kind: 'saveNote', note: { id, title: '', body: '', updatedAt: Date.now() } }).then(async () => {
              await refresh();
              setSelectedNote(id);
            });
          }}
        >{addLabel}</button>
      </div>

      {showAdd && (
        <AddEntryDialog
          onClose={() => setShowAdd(false)}
          onAdd={async (e) => {
            const r = await sendMessage({ kind: 'addEntry', entry: e });
            if (r.ok) { await refresh(); showToast('Added'); }
            return r;
          }}
        />
      )}

      {toast && <div class="toast success">{toast}</div>}
    </div>
  );
}
