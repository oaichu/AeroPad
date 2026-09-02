// src/lib/messages.ts
import type { CodeEntry, Note, Vault } from '../types/index.js';

export type Request =
  | { kind: 'createVault'; password: string }
  | { kind: 'unlock'; password: string }
  | { kind: 'lock' }
  | { kind: 'isUnlocked' }
  | { kind: 'getCodes' }
  | { kind: 'getCode'; id: string }
  | { kind: 'addEntry'; entry: Omit<CodeEntry, 'id' | 'createdAt'> }
  | { kind: 'updateEntry'; id: string; patch: Partial<CodeEntry> }
  | { kind: 'deleteEntry'; id: string }
  | { kind: 'reorderEntries'; orderedIds: string[] }
  | { kind: 'getNotes' }
  | { kind: 'saveNote'; note: Note }
  | { kind: 'deleteNote'; id: string }
  | { kind: 'exportAeropad'; password?: string }
  | { kind: 'importAeropad'; json: string; password: string; strategy: 'replace' | 'merge' }
  | { kind: 'changeMasterPassword'; oldPassword: string; newPassword: string }
  | { kind: 'fillOnTab'; tabId: number; entryId: string };

export type Response =
  | { ok: true; data?: unknown }
  | { ok: false; error: string };

export type FillRequestFromContent = {
  kind: 'fill_request';
  tabId: number;
  fieldSelector: string;
  domain: string;
};

export type FillCommandToContent = {
  kind: 'fill_command';
  code: string;
};

export type FillRequestMultipleToContent = {
  kind: 'fill_request_multiple';
  entries: Array<{ id: string; issuer: string; account: string }>;
};

export type FillRequestNoneToContent = {
  kind: 'fill_request_none';
  domain: string;
};

export type Message =
  | Request
  | FillRequestFromContent
  | FillCommandToContent
  | FillRequestMultipleToContent
  | FillRequestNoneToContent;

const VALID_KINDS: ReadonlySet<string> = new Set<string>([
  'createVault', 'unlock', 'lock', 'isUnlocked', 'getCodes', 'getCode',
  'addEntry', 'updateEntry', 'deleteEntry', 'reorderEntries',
  'getNotes', 'saveNote', 'deleteNote',
  'exportAeropad', 'importAeropad', 'changeMasterPassword', 'fillOnTab',
  'fill_request', 'fill_command',
  'fill_request_multiple', 'fill_request_none',
]);

export function isMessage(x: unknown): x is Message {
  if (typeof x !== 'object' || x === null) return false;
  const k = (x as { kind?: unknown }).kind;
  return typeof k === 'string' && VALID_KINDS.has(k);
}