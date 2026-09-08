import { useEffect, useState } from 'preact/hooks';
import { UnlockDialog } from './components/UnlockDialog.js';
import { CreateVaultDialog } from './components/CreateVaultDialog.js';
import { CodeList } from './components/CodeList.js';
import { NotesList } from './components/NotesList.js';
import { NoteEditor } from './components/NoteEditor.js';
import { AddEntryDialog } from './components/AddEntryDialog.js';
import { EditEntryDialog } from './components/EditEntryDialog.js';
import {
  ShieldIcon,
  LockIcon,
  SettingsIcon,
  SearchIcon,
  CloseIcon,
  PlusIcon,
  CheckIcon,
} from './components/Icons.js';
import { sendMessage } from '../lib/send-message.js';
import type { CodeEntry, Note } from '../types/index.js';

type Status = 'no-vault' | 'locked' | 'unlocked';

export function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [tab, setTab] = useState<'codes' | 'notes'>('codes');
  const [codes, setCodes] = useState<CodeEntry[]>([]);
  const [notes, setNotes] = useState<Note[]>([]);
  const [selectedNote, setSelectedNote] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [editingEntry, setEditingEntry] = useState<CodeEntry | null>(null);
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
    setTimeout(() => setToast(null), 1800);
  };

  useEffect(() => {
    sendMessage({ kind: 'isUnlocked' }).then((r) => {
      if (r.ok && (r.data === 'no-vault' || r.data === 'locked' || r.data === 'unlocked')) {
        setStatus(r.data);
        if (r.data === 'unlocked') void refresh();
      }
    });
  }, []);

  if (status === null) {
    return (
      <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:240px;gap:8px">
        <div class="brand-icon" style="width:36px;height:36px">
          <ShieldIcon size={20} />
        </div>
        <p class="muted" style="font-size:12px">Loading vault…</p>
      </div>
    );
  }

  if (status === 'no-vault') {
    return (
      <CreateVaultDialog
        onSubmit={async (pw) => {
          const r = await sendMessage({ kind: 'createVault', password: pw });
          if (r.ok) {
            setStatus('unlocked');
            void refresh();
            showToast('Vault created successfully');
          }
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
          if (r.ok) {
            setStatus('unlocked');
            void refresh();
          }
          return r;
        }}
      />
    );
  }

  const q = searchQuery.trim().toLowerCase();
  const filteredCodes = q
    ? codes.filter((c) => c.issuer.toLowerCase().includes(q) || c.account.toLowerCase().includes(q))
    : codes;

  const filteredNotes = q
    ? notes.filter((n) => n.title.toLowerCase().includes(q) || n.body.toLowerCase().includes(q))
    : notes;

  const currentNote = selectedNote ? notes.find((n) => n.id === selectedNote) ?? null : null;

  const handleDeleteEntry = async (id: string) => {
    const entry = codes.find((c) => c.id === id);
    const confirmName = entry ? entry.issuer || 'this account' : 'this account';
    if (!window.confirm(`Delete 2FA account for "${confirmName}"?`)) return;
    const r = await sendMessage({ kind: 'deleteEntry', id });
    if (r.ok) {
      await refresh();
      showToast('Account deleted');
    }
  };

  const handleDeleteNote = async (id: string) => {
    if (!window.confirm('Delete this encrypted note?')) return;
    const r = await sendMessage({ kind: 'deleteNote', id });
    if (r.ok) {
      if (selectedNote === id) setSelectedNote(null);
      await refresh();
      showToast('Note deleted');
    }
  };

  return (
    <div style="display:flex;flex-direction:column;flex:1;min-height:0;height:100%;overflow:hidden">
      {/* Top Header */}
      <div class="header">
        <div class="brand-badge">
          <div class="brand-icon">
            <ShieldIcon size={17} />
          </div>
          <div class="brand-title">
            AeroPad
            <span class="status-dot" title="Vault unlocked and active" />
          </div>
        </div>

        <div class="header-actions">
          <button
            class="icon-btn"
            onClick={async () => {
              await sendMessage({ kind: 'lock' });
              setStatus('locked');
            }}
            title="Lock vault now"
            aria-label="Lock vault now"
          >
            <LockIcon size={16} />
          </button>
          <button
            class="icon-btn"
            onClick={() => chrome.runtime.openOptionsPage()}
            title="Settings & backup"
            aria-label="Settings"
          >
            <SettingsIcon size={16} />
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div class="search-box">
        <span class="search-icon">
          <SearchIcon size={15} />
        </span>
        <input
          type="text"
          value={searchQuery}
          onInput={(e) => setSearchQuery((e.target as HTMLInputElement).value)}
          placeholder={tab === 'codes' ? 'Search 2FA accounts…' : 'Search notes…'}
        />
        {searchQuery.length > 0 && (
          <button
            type="button"
            class="clear-btn"
            onClick={() => setSearchQuery('')}
            aria-label="Clear search"
          >
            <CloseIcon size={14} />
          </button>
        )}
      </div>

      {/* Segmented Tabs */}
      <div class="segmented-tabs" role="tablist">
        <button
          role="tab"
          aria-selected={tab === 'codes'}
          class={tab === 'codes' ? 'active' : ''}
          onClick={() => setTab('codes')}
        >
          2FA Codes
          <span class="tab-badge">{codes.length}</span>
        </button>
        <button
          role="tab"
          aria-selected={tab === 'notes'}
          class={tab === 'notes' ? 'active' : ''}
          onClick={() => setTab('notes')}
        >
          Notes
          <span class="tab-badge">{notes.length}</span>
        </button>
      </div>

      {/* Tab Content Container */}
      <div style="display:flex;flex-direction:column;flex:1;min-height:0;overflow:hidden">
        {tab === 'codes' ? (
          <CodeList
            entries={filteredCodes}
            searchQuery={searchQuery}
            onEdit={(entry) => setEditingEntry(entry)}
            onDelete={handleDeleteEntry}
            onCopy={() => showToast('Copied to clipboard')}
          />
        ) : (
          <div class="notes-container">
            {notes.length === 0 ? (
              <NotesList
                notes={filteredNotes}
                searchQuery={searchQuery}
                selectedId={selectedNote}
                onSelect={setSelectedNote}
                onDelete={handleDeleteNote}
              />
            ) : (
              <>
                <NotesList
                  notes={filteredNotes}
                  searchQuery={searchQuery}
                  selectedId={selectedNote}
                  onSelect={setSelectedNote}
                  onDelete={handleDeleteNote}
                />
                {currentNote ? (
                  <NoteEditor
                    note={currentNote}
                    onChange={async (n) => {
                      const r = await sendMessage({ kind: 'saveNote', note: n });
                      if (r.ok) {
                        await refresh();
                      } else {
                        showToast('Failed to save note');
                      }
                    }}
                    onDelete={handleDeleteNote}
                  />
                ) : (
                  <div class="empty-box" style="flex:1">
                    <strong style="color:var(--fg);font-size:12px">Select a note</strong>
                    <span class="muted" style="font-size:11px">Choose a note from the left sidebar to read or edit</span>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>

      {/* Bottom Action Dock */}
      <div class="bottom-dock">
        <button
          onClick={async () => {
            if (tab === 'codes') {
              setShowAdd(true);
              return;
            }
            const id = crypto.randomUUID();
            const newNote: Note = { id, title: '', body: '', updatedAt: Date.now() };
            const r = await sendMessage({ kind: 'saveNote', note: newNote });
            if (r.ok) {
              await refresh();
              setSelectedNote(id);
              showToast('Note created');
            } else {
              showToast('Failed to create note');
            }
          }}
        >
          <PlusIcon size={15} />
          {tab === 'codes' ? 'Add account' : 'New note'}
        </button>
      </div>

      {/* Add Entry Modal */}
      {showAdd && (
        <AddEntryDialog
          onClose={() => setShowAdd(false)}
          onAdd={async (e) => {
            const r = await sendMessage({ kind: 'addEntry', entry: e });
            if (r.ok) {
              await refresh();
              showToast('Account added successfully');
            }
            return r;
          }}
        />
      )}

      {/* Edit Entry Modal */}
      {editingEntry && (
        <EditEntryDialog
          entry={editingEntry}
          onClose={() => setEditingEntry(null)}
          onSave={async (id, patch) => {
            const r = await sendMessage({ kind: 'updateEntry', id, patch });
            if (r.ok) {
              await refresh();
              showToast('Account updated');
            }
            return r;
          }}
        />
      )}

      {/* Toast Notice */}
      {toast && (
        <div class="toast-notice">
          <CheckIcon size={14} style="color:var(--success)" />
          <span>{toast}</span>
        </div>
      )}
    </div>
  );
}
