// src/types/index.ts
export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

export interface CodeEntry {
  id: string;
  issuer: string;
  account: string;
  secret: string;          // base32
  algorithm: TotpAlgorithm;
  digits: 6 | 8;
  period: number;          // seconds
  createdAt: number;
}

export interface Note {
  id: string;
  title: string;
  body: string;
  updatedAt: number;
}

export interface Vault {
  codes: CodeEntry[];
  notes: Note[];
}

export interface VaultBlob {
  v: 1;
  salt: string;            // base64url
  iv: string;              // base64url
  ciphertext: string;      // base64url
}

export interface VaultMeta {
  version: 1;
  kdfParams: { algo: 'PBKDF2-SHA256'; iter: 600_000 };
  createdAt: number;
  modifiedAt: number;
  entryCount: number;
}

export interface Device {
  id: string;
  name: string;
  lastSeen: number;
}

const MAX_STR = 512;
const MAX_BODY = 64 * 1024;
const MAX_ENTRIES = 10_000;

export function isCodeEntry(x: unknown): x is CodeEntry {
  if (typeof x !== 'object' || x === null) return false;
  const o = x as Record<string, unknown>;
  return typeof o.id === 'string' && o.id.length > 0 && o.id.length <= 128
    && typeof o.issuer === 'string' && o.issuer.length <= MAX_STR
    && typeof o.account === 'string' && o.account.length <= MAX_STR
    && typeof o.secret === 'string' && o.secret.length <= MAX_STR
    && (o.algorithm === 'SHA1' || o.algorithm === 'SHA256' || o.algorithm === 'SHA512')
    && (o.digits === 6 || o.digits === 8)
    && typeof o.period === 'number' && o.period >= 5 && o.period <= 3600
    && typeof o.createdAt === 'number';
}

export function isNote(x: unknown): x is Note {
  if (typeof x !== 'object' || x === null) return false;
  const o = x as Record<string, unknown>;
  return typeof o.id === 'string' && o.id.length > 0 && o.id.length <= 128
    && typeof o.title === 'string' && o.title.length <= MAX_STR
    && typeof o.body === 'string' && o.body.length <= MAX_BODY
    && typeof o.updatedAt === 'number';
}

export function isVault(x: unknown): x is Vault {
  if (typeof x !== 'object' || x === null) return false;
  const o = x as Record<string, unknown>;
  return Array.isArray(o.codes) && Array.isArray(o.notes)
    && o.codes.length <= MAX_ENTRIES && o.notes.length <= MAX_ENTRIES
    && o.codes.every(isCodeEntry) && o.notes.every(isNote);
}