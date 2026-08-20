/**
 * Smart Notepad Manager & Data Operations
 */

export class NotesManager {
  constructor(initialNotes = []) {
    this.notes = Array.isArray(initialNotes) ? [...initialNotes] : [];
  }

  getAllNotes() {
    return this.notes;
  }

  getNoteById(id) {
    return this.notes.find(n => n.id === id) || null;
  }

  createNote(title = 'Ghi chú không tiêu đề', content = '') {
    const newNote = {
      id: 'note-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7),
      title: title.trim(),
      content: content,
      updatedAt: Date.now()
    };
    this.notes.unshift(newNote);
    return newNote;
  }

  updateNote(id, fields = {}) {
    const note = this.getNoteById(id);
    if (!note) return null;

    if (fields.title !== undefined) note.title = fields.title.trim();
    if (fields.content !== undefined) note.content = fields.content;
    if (fields.tags !== undefined) note.tags = fields.tags;
    note.updatedAt = Date.now();

    return note;
  }

  deleteNote(id) {
    const index = this.notes.findIndex(n => n.id === id);
    if (index === -1) return false;
    this.notes.splice(index, 1);
    return true;
  }

  searchNotes(query = '') {
    if (!query) return this.notes;
    const lower = query.toLowerCase();
    return this.notes.filter(n =>
      n.title.toLowerCase().includes(lower) ||
      n.content.toLowerCase().includes(lower)
    );
  }
}

export function calculateMetrics(text = '') {
  const trimmed = (text || '').trim();
  const words = trimmed ? trimmed.split(/\s+/).length : 0;
  const characters = (text || '').length;
  const readTimeMinutes = Math.max(1, Math.ceil(words / 200));

  return {
    words,
    characters,
    readTimeMinutes
  };
}

export function formatExportPayload(note, type = 'md') {
  if (!note) return { filename: 'empty.txt', content: '', mimeType: 'text/plain' };

  const safeTitle = (note.title || 'Untitled').replace(/\s+/g, '_');
  let filename = safeTitle;
  let content = '';
  let mimeType = 'text/plain';

  switch (type) {
    case 'md':
      content = `# ${note.title}\n\n${note.content}`;
      filename += '.md';
      mimeType = 'text/markdown';
      break;
    case 'txt':
      content = `${note.title}\n\n${note.content}`;
      filename += '.txt';
      mimeType = 'text/plain';
      break;
    case 'json':
      content = JSON.stringify(note, null, 2);
      filename += '.json';
      mimeType = 'application/json';
      break;
    default:
      content = note.content;
      filename += '.txt';
  }

  return { filename, content, mimeType };
}
