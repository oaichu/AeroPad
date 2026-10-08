// src/background/service-worker.ts
import type { Vault } from '../types/index.js';
import { isCodeEntry } from '../types/index.js';
import type { CodeEntry, Note } from '../types/index.js';
import type { Request, Response, FillRequestFromContent } from '../lib/messages.js';
import { KDF_ITERATIONS, deriveKey, encrypt, decrypt, randomBytes, bytesToBase64Url, base64UrlToBytes } from '../lib/crypto.js';
import { getVaultBlob, setVaultBlob, getVaultMeta, setVaultMeta, getDeviceList, setDeviceList, getSessionLock, setSessionLock } from '../lib/storage.js';
import { currentCode } from '../lib/totp.js';
import { matchEntryForDomain } from '../lib/domain-match.js';
import { exportVault, importVault } from '../lib/aeropad-format.js';

interface State {
  key: CryptoKey | null;
  vault: Vault | null;
  autoLockTimer: ReturnType<typeof setTimeout> | null;
}

const state: State = { key: null, vault: null, autoLockTimer: null };

export function resetForTests(): void {
  state.key = null;
  state.vault = null;
  if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
  state.autoLockTimer = null;
}

async function encryptAndPersist(opts: { salt?: Uint8Array } = {}): Promise<void> {
  if (!state.key || !state.vault) throw new Error('Locked');
  // Reuse the existing salt so the in-memory key remains consistent with
  // the stored blob. The caller may pass `salt` to rotate it (used by
  // changeMasterPassword so the new key + new salt stay in sync).
  const existing = await getVaultBlob();
  const salt = opts.salt ?? (existing ? base64UrlToBytes(existing.salt) : randomBytes(16));
  const { iv, ciphertext } = await encrypt(new TextEncoder().encode(JSON.stringify(state.vault)), state.key);
  await setVaultBlob({ v: 1, salt: bytesToBase64Url(salt), iv: bytesToBase64Url(iv), ciphertext: bytesToBase64Url(ciphertext) });
  const meta = await getVaultMeta();
  await setVaultMeta({
    version: 1,
    kdfParams: { algo: 'PBKDF2-SHA256', iter: KDF_ITERATIONS },
    createdAt: meta?.createdAt ?? Date.now(),
    modifiedAt: Date.now(),
    entryCount: state.vault.codes.length,
  });
}

function scheduleAutoLock(): void {
  if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
  getSessionLock().then(({ autoLockMinutes }) => {
    if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
    state.autoLockTimer = setTimeout(() => { state.key = null; state.vault = null; }, autoLockMinutes * 60_000);
  });
}

async function handleFillRequest(msg: FillRequestFromContent, senderDomain?: string): Promise<Response> {
  if (!state.vault) return { ok: false, error: 'locked' };
  // Prefer the tab's real URL over the message body — a content script could
  // lie about msg.domain to phish codes for other sites' entries.
  const matches = matchEntryForDomain(state.vault.codes, senderDomain ?? msg.domain);
  if (matches.length === 0) {
    return { ok: true, data: { kind: 'fill_request_none', domain: msg.domain } };
  }
  if (matches.length === 1) {
    const entry = matches[0]!;
    const code = await currentCode(entry);
    return { ok: true, data: { kind: 'fill_command', code } };
  }
  return {
    ok: true,
    data: {
      kind: 'fill_request_multiple',
      entries: matches.map((e) => ({ id: e.id, issuer: e.issuer, account: e.account })),
    },
  };
}

export async function handleMessage(msg: Request): Promise<Response> {
  try {
    switch (msg.kind) {
      case 'createVault': {
        if (typeof msg.password !== 'string' || msg.password.length < 8) {
          return { ok: false, error: 'weak_password' };
        }
        const salt = randomBytes(16);
        const key = await deriveKey(msg.password, salt, KDF_ITERATIONS);
        const vault: Vault = { codes: [], notes: [] };
        const { iv, ciphertext } = await encrypt(new TextEncoder().encode(JSON.stringify(vault)), key);
        await setVaultBlob({ v: 1, salt: bytesToBase64Url(salt), iv: bytesToBase64Url(iv), ciphertext: bytesToBase64Url(ciphertext) });
        await setVaultMeta({ version: 1, kdfParams: { algo: 'PBKDF2-SHA256', iter: KDF_ITERATIONS }, createdAt: Date.now(), modifiedAt: Date.now(), entryCount: 0 });
        state.key = key; state.vault = vault;
        await setDeviceList([...(await getDeviceList()), { id: crypto.randomUUID(), name: 'this-device', lastSeen: Date.now() }]);
        scheduleAutoLock();
        return { ok: true };
      }
      case 'unlock': {
        try {
          const blob = await getVaultBlob();
          if (!blob) return { ok: false, error: 'wrong_password' };
          const key = await deriveKey(msg.password, base64UrlToBytes(blob.salt));
          const plaintext = await decrypt(base64UrlToBytes(blob.ciphertext), base64UrlToBytes(blob.iv), key);
          state.vault = JSON.parse(new TextDecoder().decode(plaintext));
          state.key = key;
        } catch { state.vault = null; state.key = null; return { ok: false, error: 'wrong_password' }; }
        scheduleAutoLock();
        return { ok: true };
      }
      case 'lock':
        state.key = null; state.vault = null;
        if (state.autoLockTimer) { clearTimeout(state.autoLockTimer); state.autoLockTimer = null; }
        return { ok: true };
      case 'isUnlocked': {
        const blob = await getVaultBlob();
        if (!blob) return { ok: true, data: 'no-vault' as const };
        if (state.vault === null) return { ok: true, data: 'locked' as const };
        return { ok: true, data: 'unlocked' as const };
      }
      case 'addEntry': {
        if (!state.vault) return { ok: false, error: 'locked' };
        const entry: CodeEntry = { ...msg.entry, id: crypto.randomUUID(), createdAt: Date.now() };
        if (!isCodeEntry(entry)) return { ok: false, error: 'invalid_entry' };
        state.vault.codes.push(entry);
        await encryptAndPersist();
        return { ok: true, data: entry };
      }
      case 'updateEntry': {
        if (!state.vault) return { ok: false, error: 'locked' };
        const i = state.vault.codes.findIndex((c) => c.id === msg.id);
        if (i < 0) return { ok: false, error: 'not_found' };
        const merged: CodeEntry = { ...state.vault.codes[i]!, ...msg.patch };
        if (!isCodeEntry(merged)) return { ok: false, error: 'invalid_entry' };
        state.vault.codes[i] = merged;
        await encryptAndPersist();
        return { ok: true };
      }
      case 'deleteEntry': {
        if (!state.vault) return { ok: false, error: 'locked' };
        state.vault.codes = state.vault.codes.filter((c) => c.id !== msg.id);
        await encryptAndPersist();
        return { ok: true };
      }
      case 'reorderEntries': {
        if (!state.vault) return { ok: false, error: 'locked' };
        const map = new Map(state.vault.codes.map((c) => [c.id, c] as const));
        state.vault.codes = msg.orderedIds
          .map((id) => map.get(id))
          .filter((c): c is CodeEntry => c !== undefined);
        await encryptAndPersist();
        return { ok: true };
      }
      case 'getCodes': {
        if (!state.vault) return { ok: false, error: 'locked' };
        return { ok: true, data: state.vault.codes };
      }
      case 'getCode': {
        if (!state.vault) return { ok: false, error: 'locked' };
        const c = state.vault.codes.find((x) => x.id === msg.id);
        if (!c) return { ok: false, error: 'not_found' };
        return { ok: true, data: { entry: c, code: await currentCode(c) } };
      }
      case 'getNotes': {
        if (!state.vault) return { ok: false, error: 'locked' };
        return { ok: true, data: state.vault.notes };
      }
      case 'saveNote': {
        if (!state.vault) return { ok: false, error: 'locked' };
        const i = state.vault.notes.findIndex((n) => n.id === msg.note.id);
        if (i >= 0) state.vault.notes[i] = msg.note;
        else state.vault.notes.push(msg.note);
        await encryptAndPersist();
        return { ok: true };
      }
      case 'deleteNote': {
        if (!state.vault) return { ok: false, error: 'locked' };
        state.vault.notes = state.vault.notes.filter((n: Note) => n.id !== msg.id);
        await encryptAndPersist();
        return { ok: true };
      }
      case 'exportAeropad': {
        if (!state.vault) return { ok: false, error: 'locked' };
        if (typeof msg.password !== 'string' || msg.password.length < 8) {
          return { ok: false, error: 'export_password_required' };
        }
        return { ok: true, data: await exportVault(state.vault, msg.password) };
      }
      case 'importAeropad': {
        let incoming: Vault;
        try {
          incoming = await importVault(msg.json, msg.password);
        } catch (e) {
          return { ok: false, error: e instanceof Error ? e.message : 'import_failed' };
        }
        if (msg.strategy === 'replace' && state.vault && state.key) {
          // Replacing an unlocked vault keeps the existing master password —
          // the import password only unwraps the file. Silently re-keying the
          // vault to the backup password (or worse, a weak/empty one) would
          // downgrade the user's protection without their knowledge.
          state.vault = incoming;
          await encryptAndPersist();
        } else if (msg.strategy === 'replace') {
          // Locked replace: vault password becomes the backup password.
          if (msg.password.length < 8) return { ok: false, error: 'weak_password' };
          const newSalt = randomBytes(16);
          state.key = await deriveKey(msg.password, newSalt, KDF_ITERATIONS);
          state.vault = incoming;
          await encryptAndPersist({ salt: newSalt });
        } else {
          if (!state.vault) return { ok: false, error: 'locked' };
          const ids = new Set(state.vault.codes.map((c) => c.id));
          state.vault.codes.push(...incoming.codes.filter((c) => !ids.has(c.id)));
          const nIds = new Set(state.vault.notes.map((n) => n.id));
          state.vault.notes.push(...incoming.notes.filter((n) => !nIds.has(n.id)));
          await encryptAndPersist();
        }
        scheduleAutoLock();
        return { ok: true };
      }
      case 'changeMasterPassword': {
        if (!state.vault) return { ok: false, error: 'locked' };
        // Ruling 2: verify the old password by attempting to decrypt the
        // vault with a key re-derived from the old password + current salt.
        const blob = await getVaultBlob();
        if (!blob) return { ok: false, error: 'no_vault' };
        try {
          const oldKey = await deriveKey(msg.oldPassword, base64UrlToBytes(blob.salt));
          await decrypt(base64UrlToBytes(blob.ciphertext), base64UrlToBytes(blob.iv), oldKey);
        } catch {
          return { ok: false, error: 'wrong_password' };
        }
        // Verified; re-derive with new password and rotate the salt together.
        if (typeof msg.newPassword !== 'string' || msg.newPassword.length < 8) {
          return { ok: false, error: 'weak_password' };
        }
        const newSalt = randomBytes(16);
        state.key = await deriveKey(msg.newPassword, newSalt, KDF_ITERATIONS);
        await encryptAndPersist({ salt: newSalt });
        return { ok: true };
      }
      case 'fillOnTab': {
        if (!state.vault) return { ok: false, error: 'locked' };
        const c = state.vault.codes.find((x) => x.id === msg.entryId);
        if (!c) return { ok: false, error: 'not_found' };
        const code = await currentCode(c);
        await chrome.tabs.sendMessage(msg.tabId, { kind: 'fill_command', code });
        return { ok: true };
      }
      default:
        return { ok: false, error: 'not_implemented_in_this_task' };
    }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'unknown' };
  }
}

function senderHostname(sender: chrome.runtime.MessageSender): string | undefined {
  try {
    const url = sender.tab?.url ?? sender.url;
    return url ? new URL(url).hostname : undefined;
  } catch {
    return undefined;
  }
}

chrome.runtime.onMessage.addListener((
  msg: Request | FillRequestFromContent,
  sender,
  sendResponse: (response?: unknown) => void,
) => {
  if (msg.kind === 'fill_request') {
    handleFillRequest(msg, senderHostname(sender)).then(sendResponse);
    return true;
  }
  handleMessage(msg).then(sendResponse);
  return true;
});

// Keyboard shortcut "fill-current": fill the best-matching code into the
// active tab's detected 2FA field.
chrome.commands?.onCommand.addListener(async (command: string) => {
  if (command !== 'fill-current' || !state.vault) return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url) return;
  let host: string;
  try { host = new URL(tab.url).hostname; } catch { return; }
  const matches = matchEntryForDomain(state.vault.codes, host);
  if (matches.length !== 1) return;
  const code = await currentCode(matches[0]!);
  await chrome.tabs.sendMessage(tab.id, { kind: 'fill_command', code });
});