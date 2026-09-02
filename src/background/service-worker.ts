// src/background/service-worker.ts
import type { Vault } from '../types/index.js';
import type { Request, Response, FillRequestFromContent } from '../lib/messages.js';
import { KDF_ITERATIONS, deriveKey, encrypt, decrypt, randomBytes, bytesToBase64Url, base64UrlToBytes } from '../lib/crypto.js';
import { getVaultBlob, setVaultBlob, getVaultMeta, setVaultMeta, getDeviceList, setDeviceList, getSessionLock, setSessionLock } from '../lib/storage.js';
import { currentCode } from '../lib/totp.js';
import { matchEntryForDomain } from '../lib/domain-match.js';

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

async function loadAndDecrypt(password: string): Promise<Vault> {
  const blob = await getVaultBlob();
  if (!blob) throw new Error('No vault');
  const key = await deriveKey(password, base64UrlToBytes(blob.salt));
  const plaintext = await decrypt(base64UrlToBytes(blob.ciphertext), base64UrlToBytes(blob.iv), key);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

async function encryptAndPersist(): Promise<void> {
  if (!state.key || !state.vault) throw new Error('Locked');
  const salt = randomBytes(16);
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

async function handleFillRequest(msg: FillRequestFromContent): Promise<Response> {
  if (!state.vault) return { ok: false, error: 'locked' };
  const matches = matchEntryForDomain(state.vault.codes, msg.domain);
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
        try { state.vault = await loadAndDecrypt(msg.password); }
        catch { return { ok: false, error: 'wrong_password' }; }
        const blob = await getVaultBlob();
        state.key = await deriveKey(msg.password, base64UrlToBytes(blob!.salt));
        scheduleAutoLock();
        return { ok: true };
      }
      case 'lock':
        state.key = null; state.vault = null;
        if (state.autoLockTimer) { clearTimeout(state.autoLockTimer); state.autoLockTimer = null; }
        return { ok: true };
      case 'isUnlocked':
        return { ok: true, data: state.vault !== null };
      default:
        return { ok: false, error: 'not_implemented_in_this_task' };
    }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'unknown' };
  }
}

chrome.runtime.onMessage.addListener((
  msg: Request | FillRequestFromContent,
  _sender,
  sendResponse: (response?: unknown) => void,
) => {
  if (msg.kind === 'fill_request') {
    handleFillRequest(msg).then(sendResponse);
    return true;
  }
  handleMessage(msg).then(sendResponse);
  return true;
});