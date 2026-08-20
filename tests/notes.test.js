import test from 'node:test';
import assert from 'node:assert/strict';
import { NotesManager, calculateMetrics, formatExportPayload } from '../src/notes/notes-manager.js';

test('NotesManager - Performs CRUD operations correctly', () => {
  const manager = new NotesManager();
  
  // Create
  const note1 = manager.createNote('Tiêu đề 1', 'Nội dung ghi chú đầu tiên');
  assert.ok(note1.id.startsWith('note-'));
  assert.equal(note1.title, 'Tiêu đề 1');
  assert.equal(manager.getAllNotes().length, 1);

  // Update
  const updated = manager.updateNote(note1.id, { title: 'Tiêu đề mới', content: 'Nội dung cập nhật' });
  assert.equal(updated.title, 'Tiêu đề mới');
  assert.equal(updated.content, 'Nội dung cập nhật');

  // Find
  const found = manager.getNoteById(note1.id);
  assert.equal(found.title, 'Tiêu đề mới');

  // Search
  const results = manager.searchNotes('cập nhật');
  assert.equal(results.length, 1);

  // Delete
  const deleted = manager.deleteNote(note1.id);
  assert.equal(deleted, true);
  assert.equal(manager.getAllNotes().length, 0);
});

test('calculateMetrics - Computes word count, character count and estimated reading time', () => {
  const text = 'Hệ thống bảo mật phi tập trung Web3 và ghi chú an toàn';
  const metrics = calculateMetrics(text);

  assert.equal(metrics.words, 13);
  assert.equal(metrics.characters, text.length);
  assert.equal(metrics.readTimeMinutes, 1);
});

test('formatExportPayload - Produces markdown, plain text, and json formats', () => {
  const note = {
    id: 'note-123',
    title: 'Bảo Mật Ví Lạnh',
    content: '1. Ledger\n2. Trezor',
    updatedAt: 1724000000000
  };

  const md = formatExportPayload(note, 'md');
  assert.equal(md.content, '# Bảo Mật Ví Lạnh\n\n1. Ledger\n2. Trezor');
  assert.equal(md.filename, 'Bảo_Mật_Ví_Lạnh.md');

  const txt = formatExportPayload(note, 'txt');
  assert.equal(txt.content, 'Bảo Mật Ví Lạnh\n\n1. Ledger\n2. Trezor');

  const json = formatExportPayload(note, 'json');
  assert.ok(json.content.includes('"id": "note-123"'));
});
