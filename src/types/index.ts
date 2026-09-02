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

export function isCodeEntry(x: unknown): x is CodeEntry {
  if (typeof x !== 'object' || x === null) return false;
  const o = x as Record<string, unknown>;
  return typeof o.id === 'string'
    && typeof o.issuer === 'string'
    && typeof o.account === 'string'
    && typeof o.secret === 'string'
    && (o.algorithm === 'SHA1' || o.algorithm === 'SHA256' || o.algorithm === 'SHA512')
    && (o.digits === 6 || o.digits === 8)
    && typeof o.period === 'number'
    && typeof o.createdAt === 'number';
}

export function isVault(x: unknown): x is Vault {
  if (typeof x !== 'object' || x === null) return false;
  const o = x as Record<string, unknown>;
  return Array.isArray(o.codes) && Array.isArray(o.notes);
}